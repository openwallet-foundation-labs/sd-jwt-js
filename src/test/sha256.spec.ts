import { digest } from './crypto.spec';
import { bytesToHex } from '@noble/hashes/utils';
import { sha256 } from '../sha256';

describe('SHA-256 tests', () => {
  test('test#1', async () => {
    const payload = 'test1';
    const s1 = bytesToHex(await digest(payload));
    const s2 = bytesToHex(sha256(payload));
    expect(s1).toStrictEqual(s2);
  });

  test('test#1', async () => {
    const payload = 'email@email.com';
    const s1 = bytesToHex(await digest(payload));
    const ss1 = bytesToHex(await digest(s1));
    const s2 = bytesToHex(sha256(payload));
    const ss2 = bytesToHex(sha256(s2));
    expect(ss1).toStrictEqual(ss2);
  });
});
