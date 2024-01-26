import { SDJWTException } from '../error';
import { KBJwt } from '../kbjwt';
import { KB_JWT_TYP, SDJWTCompact, Verifier } from '../type';
import Crypto from 'node:crypto';

describe('KB JWT', () => {
  test('create', async () => {
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        _sd_hash: 'hash',
      },
    });

    expect(kbJwt.header).toEqual({
      typ: KB_JWT_TYP,
      alg: 'EdDSA',
    });
    expect(kbJwt.payload).toEqual({
      iat: 1,
      aud: 'aud',
      nonce: 'nonce',
      _sd_hash: 'hash',
    });
  });

  test('decode', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        _sd_hash: 'hash',
      },
    });
    const encodedKbJwt = await kbJwt.sign(privateKey);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    expect(decoded.header).toEqual({
      typ: KB_JWT_TYP,
      alg: 'EdDSA',
    });
    expect(decoded.payload).toEqual({
      iat: 1,
      aud: 'aud',
      nonce: 'nonce',
      _sd_hash: 'hash',
    });
  });

  test('verify', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        _sd_hash: 'hash',
      },
    });
    const encodedKbJwt = await kbJwt.sign(privateKey);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    const verified = await decoded.verify(publicKey);
    expect(verified).toBe(true);
  });

  test('verify failed', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        _sd_hash: '',
      },
    });
    const encodedKbJwt = await kbJwt.sign(privateKey);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    try {
      await decoded.verify(publicKey);
    } catch (e: unknown) {
      const error = e as SDJWTException;
      expect(error.message).toBe('Invalid Key Binding Jwt');
    }
  });

  test('verify with custom Verifier', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        _sd_hash: 'hash',
      },
    });

    const encodedKbJwt = await kbJwt.sign(privateKey);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    const verified = await decoded.verifyWithVerifier(testVerifier);
    expect(verified).toBe(true);
  });

  test('verify failed with custom Verifier', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: 'EdDSA',
      },
      payload: {
        iat: 1,
        aud: 'aud',
        nonce: 'nonce',
        _sd_hash: '',
      },
    });

    const encodedKbJwt = await kbJwt.sign(privateKey);
    const decoded = KBJwt.fromKBEncode(encodedKbJwt);
    try {
      await decoded.verifyWithVerifier(testVerifier);
    } catch (e: unknown) {
      const error = e as SDJWTException;
      expect(error.message).toBe('Invalid Key Binding Jwt');
    }
  });
});
