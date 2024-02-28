import { describe, expect, test } from 'vitest';
import {
  decodeJwt,
  decodeSdJwt,
  decodeSdJwtSync,
  getClaims,
  getClaimsSync,
  getSDAlgAndPayload,
  splitSdJwt,
} from '../index';
import { digest } from '@sd-jwt/crypto-nodejs';

describe('decode tests', () => {
  test('decode jwt', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c';
    const { header, payload, signature } = decodeJwt(jwt);
    expect(signature).toBeDefined();
    expect(header).toStrictEqual({ alg: 'HS256', typ: 'JWT' });
    expect(payload).toStrictEqual({
      sub: '1234567890',
      name: 'John Doe',
      iat: 1516239022,
    });
  });

  test('decode jwt with invalid input', () => {
    const jwt = 'invalid.invalid';
    expect(() => decodeJwt(jwt)).toThrow('Invalid JWT as input');
  });

  test('split sdjwt', () => {
    const sdjwt = 'h.p.s~d1~d2~';
    const { jwt, disclosures, kbJwt } = splitSdJwt(sdjwt);
    expect(jwt).toBe('h.p.s');
    expect(disclosures).toStrictEqual(['d1', 'd2']);
    expect(kbJwt).toBeUndefined();
  });

  test('split sdjwt without disclosures', () => {
    const sdjwt = 'h.p.s';
    const { jwt, disclosures, kbJwt } = splitSdJwt(sdjwt);
    expect(jwt).toBe('h.p.s');
    expect(disclosures).toStrictEqual([]);
    expect(kbJwt).toBeUndefined();
  });

  test('split sdjwt with kbjwt', () => {
    const sdjwt = 'h.p.s~d1~d2~kbh.kbp.kbs';
    const { jwt, disclosures, kbJwt } = splitSdJwt(sdjwt);
    expect(jwt).toBe('h.p.s');
    expect(disclosures).toStrictEqual(['d1', 'd2']);
    expect(kbJwt).toBe('kbh.kbp.kbs');
  });

  test('decode sdjwt', async () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJfc2QiOlsiaWQ1azZ1ZVplVTY4bExaMlU2YjJJbF9QR3ZKb1RDMlpkMkpwY0RwMzFIWSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.GiLF_HhacrstqCJ223VvWOoJJWU8qk4dYQHklSMwxv36pPF_7ER53Wbty1qYRlQ6NeMUdBRRdj9JQLLCzz1gCQ~WyI2NTMxNDA2ZmVhZmU0YjBmIiwiZm9vIiwiYmFyIl0~';
    const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
    expect(decodedSdJwt).toBeDefined();
    expect(decodedSdJwt.kbJwt).toBeUndefined();
    expect(decodedSdJwt.disclosures.length).toEqual(1);
    expect(decodedSdJwt.jwt).toBeDefined();
  });

  test('decode jwt', async () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6InNkK2p3dCJ9.eyJsYXN0bmFtZSI6IkRvZSIsInNzbiI6IjEyMy00NS02Nzg5IiwiX3NkIjpbIk4yUXhZV1UxTlRnME1qQmpOR1JpWVRCaU1tRmtaamN5WXpSbFpXUmhaRGd5WkRCbE1qaGhZVGcwTnpJMU9XSXpZek5qWkdNNE1qZG1NVGN6TmpZd05RIiwiWlRSalkyUTVOemRoWkRVM05tWTFZV0UyTmpka01XVmpNRE16WXpOak5qQmtNak5pT0dZelpHSTBOelV4TURsak9EWTRNREEzWm1JeFpUY3daREZqTmciXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.mX14Sw86xy8NFQta7tCfNmhVCqzfaJ_K3VEIhTjbLDY';
    const decodedSdJwt = await decodeSdJwt(jwt, digest);
    expect(decodedSdJwt).toBeDefined();
    expect(decodedSdJwt.kbJwt).toBeUndefined();
    expect(decodedSdJwt.disclosures.length).toEqual(0);
    expect(decodedSdJwt.jwt).toBeDefined();
  });

  test('decode sdjwt sync', () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJfc2QiOlsiaWQ1azZ1ZVplVTY4bExaMlU2YjJJbF9QR3ZKb1RDMlpkMkpwY0RwMzFIWSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.GiLF_HhacrstqCJ223VvWOoJJWU8qk4dYQHklSMwxv36pPF_7ER53Wbty1qYRlQ6NeMUdBRRdj9JQLLCzz1gCQ~WyI2NTMxNDA2ZmVhZmU0YjBmIiwiZm9vIiwiYmFyIl0~';
    const decodedSdJwt = decodeSdJwtSync(sdjwt, digest);
    expect(decodedSdJwt).toBeDefined();
    expect(decodedSdJwt.kbJwt).toBeUndefined();
    expect(decodedSdJwt.disclosures.length).toEqual(1);
    expect(decodedSdJwt.jwt).toBeDefined();
  });

  test('decode jwt sync', () => {
    const jwt =
      'eyJhbGciOiJIUzI1NiIsInR5cCI6InNkK2p3dCJ9.eyJsYXN0bmFtZSI6IkRvZSIsInNzbiI6IjEyMy00NS02Nzg5IiwiX3NkIjpbIk4yUXhZV1UxTlRnME1qQmpOR1JpWVRCaU1tRmtaamN5WXpSbFpXUmhaRGd5WkRCbE1qaGhZVGcwTnpJMU9XSXpZek5qWkdNNE1qZG1NVGN6TmpZd05RIiwiWlRSalkyUTVOemRoWkRVM05tWTFZV0UyTmpka01XVmpNRE16WXpOak5qQmtNak5pT0dZelpHSTBOelV4TURsak9EWTRNREEzWm1JeFpUY3daREZqTmciXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.mX14Sw86xy8NFQta7tCfNmhVCqzfaJ_K3VEIhTjbLDY';
    const decodedSdJwt = decodeSdJwtSync(jwt, digest);
    expect(decodedSdJwt).toBeDefined();
    expect(decodedSdJwt.kbJwt).toBeUndefined();
    expect(decodedSdJwt.disclosures.length).toEqual(0);
    expect(decodedSdJwt.jwt).toBeDefined();
  });

  test('get claims', async () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJfc2QiOlsiaWQ1azZ1ZVplVTY4bExaMlU2YjJJbF9QR3ZKb1RDMlpkMkpwY0RwMzFIWSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.GiLF_HhacrstqCJ223VvWOoJJWU8qk4dYQHklSMwxv36pPF_7ER53Wbty1qYRlQ6NeMUdBRRdj9JQLLCzz1gCQ~WyI2NTMxNDA2ZmVhZmU0YjBmIiwiZm9vIiwiYmFyIl0~';
    const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
    const claims = await getClaims(
      decodedSdJwt.jwt.payload,
      decodedSdJwt.disclosures,
      digest,
    );
    expect(claims).toStrictEqual({
      foo: 'bar',
    });
  });

  test('getClaims #2', async () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp7Il9zZCI6WyJqVEszMHNleDZhYV9kUk1KSWZDR056Q0FwbVB5MzRRNjNBa3QzS3hhSktzIl19LCJfc2QiOlsiME9nMi1ReG95eW1UOGNnVzZZUjVSSFpQLUJuR2tHUi1NM2otLV92RWlzSSIsIkcwZ3lHNnExVFMyUlQxMkZ3X2RRRDVVcjlZc1AwZlVWOXVtQWdGMC1jQ1EiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ggEyE4SeDO2Hu3tol3VLmi7NQj56yKzKQDaafocgkLrUBdivghohtzrfcbrMN7CRufJ_Cnh0EL54kymXLGTdDQ~WyIwNGU0MjAzOWU4ZWFiOWRjIiwiYSIsIjEiXQ~WyIwOGE1Yjc5MjMyYjAzYzBhIiwiMSJd~WyJiNWE2YjUzZGQwYTFmMGIwIiwienp6IiwieHh4Il0~WyIxYzdmOTE4ZTE0MjA2NzZiIiwiZm9vIiwiYmFyIl0~WyJmZjYxYzQ5ZGU2NjFiYzMxIiwiYXJyIixbeyIuLi4iOiJTSG96VW5KNUpkd0ZtTjVCbXB5dXZCWGZfZWRjckVvcExPYThTVlBFUmg0In0sIjIiLHsiX3NkIjpbIkpuODNhZkp0OGx4NG1FMzZpRkZyS2U2R2VnN0dlVUQ4Z3UwdVo3NnRZcW8iXX1dXQ~';
    const decodedSdJwt = await decodeSdJwt(sdjwt, digest);
    const claims = await getClaims(
      decodedSdJwt.jwt.payload,
      decodedSdJwt.disclosures,
      digest,
    );
    expect(claims).toStrictEqual({
      foo: 'bar',
      arr: ['1', '2', { a: '1' }],
      test: {
        zzz: 'xxx',
      },
    });
  });

  test('get claims sync', () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJfc2QiOlsiaWQ1azZ1ZVplVTY4bExaMlU2YjJJbF9QR3ZKb1RDMlpkMkpwY0RwMzFIWSJdLCJfc2RfYWxnIjoic2hhLTI1NiJ9.GiLF_HhacrstqCJ223VvWOoJJWU8qk4dYQHklSMwxv36pPF_7ER53Wbty1qYRlQ6NeMUdBRRdj9JQLLCzz1gCQ~WyI2NTMxNDA2ZmVhZmU0YjBmIiwiZm9vIiwiYmFyIl0~';
    const decodedSdJwt = decodeSdJwtSync(sdjwt, digest);
    const claims = getClaimsSync(
      decodedSdJwt.jwt.payload,
      decodedSdJwt.disclosures,
      digest,
    );
    expect(claims).toStrictEqual({
      foo: 'bar',
    });
  });

  test('getClaims sync #2', () => {
    const sdjwt =
      'eyJ0eXAiOiJzZC1qd3QiLCJhbGciOiJFZERTQSJ9.eyJ0ZXN0Ijp7Il9zZCI6WyJqVEszMHNleDZhYV9kUk1KSWZDR056Q0FwbVB5MzRRNjNBa3QzS3hhSktzIl19LCJfc2QiOlsiME9nMi1ReG95eW1UOGNnVzZZUjVSSFpQLUJuR2tHUi1NM2otLV92RWlzSSIsIkcwZ3lHNnExVFMyUlQxMkZ3X2RRRDVVcjlZc1AwZlVWOXVtQWdGMC1jQ1EiXSwiX3NkX2FsZyI6InNoYS0yNTYifQ.ggEyE4SeDO2Hu3tol3VLmi7NQj56yKzKQDaafocgkLrUBdivghohtzrfcbrMN7CRufJ_Cnh0EL54kymXLGTdDQ~WyIwNGU0MjAzOWU4ZWFiOWRjIiwiYSIsIjEiXQ~WyIwOGE1Yjc5MjMyYjAzYzBhIiwiMSJd~WyJiNWE2YjUzZGQwYTFmMGIwIiwienp6IiwieHh4Il0~WyIxYzdmOTE4ZTE0MjA2NzZiIiwiZm9vIiwiYmFyIl0~WyJmZjYxYzQ5ZGU2NjFiYzMxIiwiYXJyIixbeyIuLi4iOiJTSG96VW5KNUpkd0ZtTjVCbXB5dXZCWGZfZWRjckVvcExPYThTVlBFUmg0In0sIjIiLHsiX3NkIjpbIkpuODNhZkp0OGx4NG1FMzZpRkZyS2U2R2VnN0dlVUQ4Z3UwdVo3NnRZcW8iXX1dXQ~';
    const decodedSdJwt = decodeSdJwtSync(sdjwt, digest);
    const claims = getClaimsSync(
      decodedSdJwt.jwt.payload,
      decodedSdJwt.disclosures,
      digest,
    );
    expect(claims).toStrictEqual({
      foo: 'bar',
      arr: ['1', '2', { a: '1' }],
      test: {
        zzz: 'xxx',
      },
    });
  });

  test('Test default sd hash algorithm', () => {
    const { _sd_alg, payload } = getSDAlgAndPayload({});
    expect(_sd_alg).toBe('sha-256');
  });
});
