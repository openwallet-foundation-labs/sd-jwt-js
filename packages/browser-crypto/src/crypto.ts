export const generateSalt = (length: number): string => {
  if (length <= 0) {
    return '';
  }

  const array = new Uint8Array(length);
  globalThis.crypto.getRandomValues(array);

  const salt = Array.from(array, (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');

  return salt;
};

export async function digest(
  data: string,
  algorithm = 'SHA-256',
): Promise<Uint8Array> {
  const { subtle } = globalThis.crypto;
  const ec = new TextEncoder();
  const digest = await subtle.digest(algorithm, ec.encode(data));
  return new Uint8Array(digest);
}

export const getHasher = (algorithm = 'SHA-256') => {
  return (data: string) => digest(data, algorithm);
};

const spkiToPEM = (keyData: ArrayBuffer) => {
  const keyB64 = arrayBufferToBase64(keyData);
  const keyPem = `-----BEGIN PUBLIC KEY-----\n${formatKeyBase64(
    keyB64,
  )}\n-----END PUBLIC KEY-----`;
  return keyPem;
};

const pkcs8ToPEM = (keyData: ArrayBuffer) => {
  const keyB64 = arrayBufferToBase64(keyData);
  const keyPem = `-----BEGIN PRIVATE KEY-----\n${formatKeyBase64(
    keyB64,
  )}\n-----END PRIVATE KEY-----`;
  return keyPem;
};

const arrayBufferToBase64 = (buffer: ArrayBuffer) => {
  let binary = '';
  const bytes = new Uint8Array(buffer);
  const len = bytes.byteLength;
  for (let i = 0; i < len; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return window.btoa(binary);
};

const formatKeyBase64 = (base64str: string) => {
  const lines = base64str.match(/.{1,64}/g);
  if (!lines) {
    throw new Error('Failed to format key');
  }
  return lines.join('\n');
};

const pkcs8PemToCryptoKey = async (pem: string): Promise<CryptoKey> => {
  // Remove PEM header and footer
  const pemHeader = '-----BEGIN PRIVATE KEY-----';
  const pemFooter = '-----END PRIVATE KEY-----';
  const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '').trim();

  // Base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  const binaryDer = str2ab(binaryDerString);

  // Import the key
  return await window.crypto.subtle.importKey(
    'pkcs8',
    binaryDer,
    {
      name: 'ECDSA',
      namedCurve: 'P-256', // Applicable for ES256
    },
    true, // whether the key is extractable (i.e., can be used in exportKey)
    ['sign'], // "sign" for a private key, "verify" for a public key
  );
};

const spkiPemToCryptoKey = async (pem: string): Promise<CryptoKey> => {
  // Remove PEM header and footer
  const pemHeader = '-----BEGIN PRIVATE KEY-----';
  const pemFooter = '-----END PRIVATE KEY-----';
  const pemContents = pem.replace(pemHeader, '').replace(pemFooter, '').trim();

  // Base64 decode the string to get the binary data
  const binaryDerString = window.atob(pemContents);
  const binaryDer = str2ab(binaryDerString);

  // Import the key
  return await window.crypto.subtle.importKey(
    'spki',
    binaryDer,
    {
      name: 'ECDSA',
      namedCurve: 'P-256', // Applicable for ES256
    },
    true, // whether the key is extractable (i.e., can be used in exportKey)
    ['verify'], // "sign" for a private key, "verify" for a public key
  );
};

// Utility function to convert a string to an ArrayBuffer
const str2ab = (str: string): ArrayBuffer => {
  const buf = new ArrayBuffer(str.length);
  const bufView = new Uint8Array(buf);
  for (let i = 0, strLen = str.length; i < strLen; i++) {
    bufView[i] = str.charCodeAt(i);
  }
  return buf;
};

export const ES256 = {
  alg: 'ES256',

  async generateKeyPair() {
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: 'ECDSA',
        namedCurve: 'P-256', // ES256
      },
      true, // whether the key is extractable (i.e., can be used in exportKey)
      ['sign', 'verify'], // can be used to sign and verify signatures
    );

    const exportedPublicKey = await window.crypto.subtle.exportKey(
      'spki',
      keyPair.publicKey,
    );
    // Export the private key in PKCS8 format
    const exportedPrivateKey = await window.crypto.subtle.exportKey(
      'pkcs8',
      keyPair.privateKey,
    );

    // Convert to PEM format
    const publicKey = spkiToPEM(exportedPublicKey);
    const privateKey = pkcs8ToPEM(exportedPrivateKey);

    // Convert keys to PEM format if needed, or use them as is in ArrayBuffer format for Web Crypto operations
    return { publicKey, privateKey };
  },

  async getSigner(privateKeyPEM: string) {
    const privateKey = await pkcs8PemToCryptoKey(privateKeyPEM);
    return async (data: string) => {
      const encoder = new TextEncoder();
      const signature = await window.crypto.subtle.sign(
        {
          name: 'ECDSA',
          hash: { name: 'SHA-256' }, // Required for ES256
        },
        privateKey, // from generateKey or importKey
        encoder.encode(data), // ArrayBuffer of data you want to sign
      );

      return window
        .btoa(String.fromCharCode(...new Uint8Array(signature)))
        .replace(/\+/g, '-')
        .replace(/\//g, '_')
        .replace(/=+$/, ''); // Convert to base64url format
    };
  },

  async getVerifier(publicKeyPEM: string) {
    const publicKey = await spkiPemToCryptoKey(publicKeyPEM);
    return async (data: string, signatureBase64url: string) => {
      const encoder = new TextEncoder();
      const signature = Uint8Array.from(
        atob(signatureBase64url.replace(/-/g, '+').replace(/_/g, '/')),
        (c) => c.charCodeAt(0),
      );
      const isValid = await window.crypto.subtle.verify(
        {
          name: 'ECDSA',
          hash: { name: 'SHA-256' }, // Required for ES256
        },
        publicKey, // from generateKey or importKey
        signature, // ArrayBuffer of the signature
        encoder.encode(data), // ArrayBuffer of the data
      );

      return isValid;
    };
  },
};
