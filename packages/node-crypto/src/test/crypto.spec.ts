import { describe, expect, test } from 'vitest';
import { generateSalt, digest, ES256, Ed25519 } from '../crypto';

describe('This file is for utility functions', () => {
  test('crypto', () => {
    expect('1').toStrictEqual('1');
  });

  test('generateSalt', async () => {
    const salt = generateSalt(8);
    expect(salt).toBeDefined();
    expect(salt.length).toBe(8);
  });

  test('generateSalt 0 length', async () => {
    const salt = generateSalt(0);
    expect(salt).toBeDefined();
    expect(salt.length).toBe(0);
  });

  test('digest', async () => {
    const payload = 'test1';
    const s1 = await digest(payload);
    expect(s1).toBeDefined();
    expect(s1.length).toBe(32);
  });

  test('digest', async () => {
    const payload = 'test1';
    const s1 = await digest(payload, 'SHA512');
    expect(s1).toBeDefined();
    expect(s1.length).toBe(64);
  });

  test('Ed25519', async () => {
    const { privateKey, publicKey } = Ed25519.generateKeyPair();
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
    expect(typeof privateKey).toBe('string');
    expect(typeof publicKey).toBe('string');

    const data =
      'In cryptography, a salt is random data that is used as an additional input to a one-way function that hashes data, a password or passphrase.';
    const signature = await Ed25519.getSigner(privateKey)(data);
    expect(signature).toBeDefined();
    expect(typeof signature).toBe('string');

    const result = await Ed25519.getVerifier(publicKey)(data, signature);
    expect(result).toBe(true);
  });

  test('ES256', async () => {
    const { privateKey, publicKey } = ES256.generateKeyPair();
    expect(privateKey).toBeDefined();
    expect(publicKey).toBeDefined();
    expect(typeof privateKey).toBe('string');
    expect(typeof publicKey).toBe('string');

    const data =
      'In cryptography, a salt is random data that is used as an additional input to a one-way function that hashes data, a password or passphrase.';
    const signature = await ES256.getSigner(privateKey)(data);
    expect(signature).toBeDefined();
    expect(typeof signature).toBe('string');

    const result = await ES256.getVerifier(publicKey)(data, signature);
    expect(result).toBe(true);
  });
});
