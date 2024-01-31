import { SDJWTException } from './error';

export const generateSalt = (length: number): string => {
  if (length <= 0) {
    throw new SDJWTException('Salt length must be greater than 0.');
  }
  const Crypto = require('node:crypto');
  const saltBytes = Crypto.randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt;
};

export const digest = async (
  data: string,
  algorithm: string = 'SHA-256',
): Promise<string> => {
  const Crypto = require('node:crypto');
  const nodeAlg = toNodeCryptoAlg(algorithm);
  const hash = Crypto.createHash(nodeAlg);
  hash.update(data);
  return hash.digest('hex');
};

export const getHasher = (algorithm: string = 'SHA-256') => {
  return (data: string) => digest(data, algorithm);
};

const toNodeCryptoAlg = (hashAlg: string): string =>
  hashAlg.replace('-', '').toLowerCase();
