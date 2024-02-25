import {
  createHash,
  randomBytes,
  sign,
  verify,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
} from 'crypto';

export const generateSalt = (length: number): string => {
  if (length <= 0) {
    return '';
  }
  const saltBytes = randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt.substring(0, length);
};

export const digest = (data: string, algorithm = 'SHA-256'): Uint8Array => {
  const nodeAlg = toNodeCryptoAlg(algorithm);
  const hash = createHash(nodeAlg);
  hash.update(data);
  const hashBuffer = hash.digest();
  return new Uint8Array(hashBuffer);
};

const toNodeCryptoAlg = (hashAlg: string): string =>
  hashAlg.replace('-', '').toLowerCase();

const getSigner = (privateKeyPEM: string) => {
  const privateKey = createPrivateKey(privateKeyPEM);
  return async (data: string) => {
    const sig = sign(null, Buffer.from(data), privateKey);
    return Buffer.from(sig).toString('base64url');
  };
};

const getVerifier = (publicKeyPEM: string) => {
  const publicKey = createPublicKey(publicKeyPEM);
  return async (data: string, sig: string) => {
    return verify(
      null,
      Buffer.from(data),
      publicKey,
      Buffer.from(sig, 'base64url'),
    );
  };
};

export const Ed25519 = {
  alg: 'EdDSA',
  generateKeyPair: () => {
    return generateKeyPairSync('ed25519', {
      publicKeyEncoding: {
        type: 'spki', // Recommended format for public key
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8', // Recommended format for private key
        format: 'pem',
      },
    });
  },
  getSigner,
  getVerifier,
};

export const ES256 = {
  alg: 'ES256',
  generateKeyPair: () => {
    return generateKeyPairSync('ec', {
      namedCurve: 'P-256',
      publicKeyEncoding: {
        type: 'spki', // Recommended format for public key
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8', // Recommended format for private key
        format: 'pem',
      },
    });
  },
  getSigner,
  getVerifier,
};
