import { SDJWTException } from '../error';
import { Jwt } from '../jwt';
import Crypto from 'node:crypto';
import { Signer, Verifier } from '../type';

describe('JWT', () => {
  test('create', async () => {
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    expect(jwt.header).toEqual({ alg: 'EdDSA' });
    expect(jwt.payload).toEqual({ foo: 'bar' });
  });

  test('set', async () => {
    const jwt = new Jwt();
    jwt.setHeader({ alg: 'EdDSA' });
    jwt.setPayload({ foo: 'bar' });

    expect(jwt.header).toEqual({ alg: 'EdDSA' });
    expect(jwt.payload).toEqual({ foo: 'bar' });
  });

  test('sign', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    const encodedJwt = await jwt.sign(privateKey);
    expect(typeof encodedJwt).toBe('string');
  });

  test('verify', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    const encodedJwt = await jwt.sign(privateKey);
    const newJwt = Jwt.fromEncode(encodedJwt);
    const verified = await newJwt.verify(publicKey);
    expect(verified).toBe(true);
    const notVerified = await newJwt.verify(
      Crypto.generateKeyPairSync('ed25519').privateKey,
    );
    expect(notVerified).toBe(false);
  });

  test('encode', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    const encodedJwt = await jwt.sign(privateKey);
    const newJwt = Jwt.fromEncode(encodedJwt);
    const newEncodedJwt = newJwt.encodeJwt();
    expect(newEncodedJwt).toBe(encodedJwt);
  });

  test('decode failed', () => {
    expect(() => Jwt.fromEncode('asfasfas')).toThrow();
  });

  test('sign failed', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
    });

    try {
      await jwt.sign(privateKey);
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
    }
  });

  test('encode failed', async () => {
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
    });

    try {
      jwt.encodeJwt();
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
    }
  });

  test('verify failed', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
    });

    try {
      await jwt.verify(privateKey);
    } catch (e: unknown) {
      expect(e).toBeInstanceOf(SDJWTException);
    }
  });

  test('custom signer', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    const encodedJwt = await jwt.signWithSigner(testSigner);
    const newJwt = Jwt.fromEncode(encodedJwt);
    const verified = await newJwt.verify(publicKey);
    expect(verified).toBe(true);
  });

  test('custom verifier', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const jwt = new Jwt({
      header: { alg: 'EdDSA' },
      payload: { foo: 'bar' },
    });

    const encodedJwt = await jwt.sign(privateKey);
    const newJwt = Jwt.fromEncode(encodedJwt);
    const verified = await newJwt.verifyWithVerifier(testVerifier);
    expect(verified).toBe(true);
  });
});
