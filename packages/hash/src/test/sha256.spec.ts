import { digest } from '@sd-jwt/crypto-nodejs';
import { bytesToHex } from '@noble/hashes/utils';
import { hasher, sha256 } from '../sha256';
import { describe, expect, test } from 'vitest';

describe('SHA-256 tests', () => {
  test('test#1', async () => {
    const payload = 'test1';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#2', async () => {
    const payload = 'email@email.com';
    const s1 = bytesToHex(await digest(payload));
    const ss1 = bytesToHex(await digest(s1));
    const s2 = bytesToHex(sha256(payload));
    const ss2 = bytesToHex(sha256(s2));
    expect(ss1).toStrictEqual(ss2);
  });

  test('test#3', async () => {
    const payload = 'こんにちは';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#4', async () => {
    const payload = 'Привет Добро пожаловать';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#5', async () => {
    const payload = '🧑‍💻👩‍💻';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#6', async () => {
    const payload = 'مرحبا';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#7', async () => {
    const payload = 'שלום';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#8', async () => {
    const payload = 'स्वागत है';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#9', async () => {
    const payload = 'হ্যালো';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#10', async () => {
    const payload = 'Γειά σου';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#11', async () => {
    const payload = 'สวัสดี';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#12', async () => {
    const payload = 'Добро пожаловать';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#13', async () => {
    const payload = 'ሰላም';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#14', async () => {
    const payload = 'Բարեւ Ձեզ';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('Hasher', async () => {
    const s1 = bytesToHex(await digest('test'));
    const s2 = bytesToHex(hasher('test', 'SHA-256'));
    const s3 = bytesToHex(hasher('test', 'SHA256'));
    const s4 = bytesToHex(hasher('test', 'sha256'));
    const s5 = bytesToHex(hasher('test', 'sha-256'));
    expect(s1).toStrictEqual(s2);
    expect(s1).toStrictEqual(s3);
    expect(s1).toStrictEqual(s4);
    expect(s1).toStrictEqual(s5);
  });

  test('Hasher failed', async () => {
    try {
      const s1 = hasher('test', 'sha-512');
    } catch (e) {
      expect(e).toBeInstanceOf(Error);
    }
  });
});
