import { createHash, randomBytes } from 'crypto';

export const generateSalt = (length: number): string => {
  if (length <= 0) {
    return '';
  }
  const saltBytes = randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt.substring(0, length);
};

export const digest = (
  data: string,
  algorithm = 'SHA-256',
): Uint8Array => {
  const nodeAlg = toNodeCryptoAlg(algorithm);
  const hash = createHash(nodeAlg);
  hash.update(data);
  const hashBuffer = hash.digest();
  return new Uint8Array(hashBuffer);
};

const toNodeCryptoAlg = (hashAlg: string): string =>
  hashAlg.replace('-', '').toLowerCase();
