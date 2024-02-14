import { describe, expect, test } from 'vitest';
import { createHash, randomBytes } from 'crypto';

export const generateSalt = (length: number): string => {
  const saltBytes = randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt;
};

export const digest = async (
  data: string,
  algorithm: string = 'SHA-256',
): Promise<Uint8Array> => {
  const nodeAlg = toNodeCryptoAlg(algorithm);
  const hash = createHash(nodeAlg);
  hash.update(data);
  const hashBuffer = hash.digest();
  return new Uint8Array(hashBuffer);
};

const toNodeCryptoAlg = (hashAlg: string): string =>
  hashAlg.replace('-', '').toLowerCase();

describe('This file is for utility functions', () => {
  test('crypto', () => {
    expect('1').toStrictEqual('1');
  });
});
