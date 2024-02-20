import { describe, expect, test } from 'vitest';
import { generateSalt, digest } from '../crypto';

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
});
