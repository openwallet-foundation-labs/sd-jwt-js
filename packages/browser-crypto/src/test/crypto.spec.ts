import { describe, expect, test, it } from 'vitest';
import { generateSalt, digest, getHasher } from '../index';

// Extract the major version as a number
const nodeVersionMajor = parseInt(
  process.version.split('.')[0].substring(1),
  10,
);

describe('This file is for utility functions', () => {
  (nodeVersionMajor < 20 ? test.skip : test)('generateSalt', async () => {
    const salt = generateSalt(8);
    expect(salt).toBeDefined();
    expect(salt.length).toBe(8);
  });

  (nodeVersionMajor < 20 ? test.skip : test)(
    'generateSalt 0 length',
    async () => {
      const salt = generateSalt(0);
      expect(salt).toBeDefined();
      expect(salt.length).toBe(0);
    },
  );

  (nodeVersionMajor < 20 ? test.skip : test)('digest', async () => {
    const payload = 'test1';
    const s1 = await digest(payload);
    expect(s1).toBeDefined();
    expect(s1.length).toBe(32);
  });

  (nodeVersionMajor < 20 ? test.skip : test)('digest', async () => {
    const payload = 'test1';
    const s1 = await digest(payload, 'SHA-512');
    expect(s1).toBeDefined();
    expect(s1.length).toBe(64);
  });

  (nodeVersionMajor < 20 ? test.skip : test)('get hasher', async () => {
    const hash = await getHasher('SHA-512')('test1');
    expect(hash).toBeDefined();
  });
});
