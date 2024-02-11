import Crypto from 'node:crypto';

export const generateSalt = (length: number): string => {
  const saltBytes = Crypto.randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt;
};

function base64urlEncode(base64string: string) {
  return base64string
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

export const digest = async (
  data: string,
  algorithm: string = 'SHA-256',
): Promise<Uint8Array> => {
  const nodeAlg = toNodeCryptoAlg(algorithm);
  const hash = Crypto.createHash(nodeAlg);
  hash.update(data);
  const hashBuffer = hash.digest();
  return new Uint8Array(hashBuffer);
};

export const getHasher = (algorithm: string = 'SHA-256') => {
  return (data: string) => digest(data, algorithm);
};

const toNodeCryptoAlg = (hashAlg: string): string =>
  hashAlg.replace('-', '').toLowerCase();

describe('This file is for utility functions', () => {
  test('crypto', () => {
    expect('1').toStrictEqual('1');
  });
});
