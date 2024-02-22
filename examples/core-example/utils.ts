import Crypto from 'crypto';
import { Signer, Verifier } from '@hopae/sd-jwt-type';

export const createSignerVerifier = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  const signer: Signer = async (data: string) => {
    const sig = Crypto.sign(null, Buffer.from(data), privateKey);
    return Buffer.from(sig).toString('base64url');
  };
  const verifier: Verifier = async (data: string, sig: string) => {
    return Crypto.verify(
      null,
      Buffer.from(data),
      publicKey,
      Buffer.from(sig, 'base64url'),
    );
  };
  return { signer, verifier };
};

export const generateSalt = (length: number): string => {
  const saltBytes = Crypto.randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt;
};

export const digest = async (
  data: string,
  algorithm = 'SHA-256',
): Promise<Uint8Array> => {
  const nodeAlg = toNodeCryptoAlg(algorithm);
  const hash = Crypto.createHash(nodeAlg);
  hash.update(data);
  const hashBuffer = hash.digest();
  return new Uint8Array(hashBuffer);
};

const toNodeCryptoAlg = (hashAlg: string): string =>
  hashAlg.replace('-', '').toLowerCase();
