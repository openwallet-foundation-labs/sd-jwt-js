import {
  createHash,
  randomBytes,
  sign,
  verify,
  generateKeyPairSync,
  createPublicKey,
  createPrivateKey,
  KeyObject,
} from 'crypto';
import {
  exportJWK,
  importJWK,
  JWK,
  exportPKCS8,
  exportSPKI,
  KeyLike,
} from 'jose';

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

async function jwkToPem(jwk: JWK) {
  const key = (await importJWK(jwk, jwk.alg)) as KeyLike;

  if (jwk.d) {
    // Private Key
    return await exportPKCS8(key);
  } else {
    // Public Key
    return await exportSPKI(key);
  }
}

async function pemToJwk(pem: string) {
  let keyObj: KeyObject;
  try {
    keyObj = createPublicKey(pem);
  } catch {
    keyObj = createPrivateKey(pem);
  }

  const jwk = await exportJWK(keyObj);
  return jwk;
}

const getSigner = async (privateKeyJWK: JWK) => {
  const ecPrivateKey = await jwkToPem(privateKeyJWK);
  return async (data: string) => {
    const sig = sign(null, Buffer.from(data), ecPrivateKey);
    return Buffer.from(sig).toString('base64url');
  };
};

const getVerifier = async (publicKeyJWK: JWK) => {
  const ecPublicKey = await jwkToPem(publicKeyJWK);
  return async (data: string, sig: string) => {
    return verify(
      null,
      Buffer.from(data),
      ecPublicKey,
      Buffer.from(sig, 'base64url'),
    );
  };
};

export const Ed25519 = {
  alg: 'EdDSA',
  generateKeyPair: async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ed25519', {
      publicKeyEncoding: {
        type: 'spki', // Recommended format for public key
        format: 'pem',
      },
      privateKeyEncoding: {
        type: 'pkcs8', // Recommended format for private key
        format: 'pem',
      },
    });
    return {
      privateKey: await pemToJwk(privateKey),
      publicKey: await pemToJwk(publicKey),
    };
  },
  getSigner,
  getVerifier,
};

export const ES256 = {
  alg: 'ES256',
  generateKeyPair: async () => {
    const { privateKey, publicKey } = generateKeyPairSync('ec', {
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
    return {
      privateKey: await pemToJwk(privateKey),
      publicKey: await pemToJwk(publicKey),
    };
  },
  getSigner,
  getVerifier,
};
