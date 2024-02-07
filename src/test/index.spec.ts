import sdjwt, { Signer, Verifier } from '../index';
import Crypto from 'node:crypto';

describe('index', () => {
  test('create', async () => {
    const SDJwtInstance = sdjwt.create({
      omitTyp: true,
    });
    expect(SDJwtInstance).toBeDefined();
  });

  test('kbJwt', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      { privateKey },
      {
        _sd: ['foo'],
      },
    );

    expect(credential).toBeDefined();

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        alg: 'EdDSA',
        payload: {
          sd_hash: 'sha-256',
          aud: '1',
          iat: 1,
          nonce: '342',
        },
        privateKey,
      },
    });

    expect(presentation).toBeDefined();
  });

  test('kbJwt with custom signer', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      { privateKey },
      {
        _sd: ['foo'],
      },
    );

    expect(credential).toBeDefined();

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        alg: 'EdDSA',
        payload: {
          sd_hash: 'sha-256',
          aud: '1',
          iat: 1,
          nonce: '342',
        },
        signer: testSigner,
      },
    });

    expect(presentation).toBeDefined();
  });

  test('issue with signer', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      { signer: testSigner },
      {
        _sd: ['foo'],
      },
    );

    expect(credential).toBeDefined();
  });

  test('issue with signer in config', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const testSigner: Signer = async (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };
    const SDJwtInstance = sdjwt.create({
      signer: testSigner,
    });
    const credential = await SDJwtInstance.issue(
      {
        foo: 'bar',
      },
      undefined,
      {
        _sd: ['foo'],
      },
    );

    expect(credential).toBeDefined();
  });

  test('verify failed', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      { privateKey },
      {
        _sd: ['foo'],
      },
    );

    try {
      await sdjwt.verify(credential, {
        publicKey: Crypto.generateKeyPairSync('ed25519').privateKey,
      });
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('verify failed with kbJwt', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      { privateKey },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        alg: 'EdDSA',
        payload: {
          sd_hash: '',
          aud: '1',
          iat: 1,
          nonce: '342',
        },
        privateKey,
      },
    });

    try {
      await sdjwt.verify(presentation, { publicKey });
    } catch (e) {
      expect(e).toBeDefined();
    }
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

    const credential = await sdjwt.issue({ foo: 'bar' }, { privateKey });

    const verified = await sdjwt.verify(credential, { verifier: testVerifier });

    expect(verified).toStrictEqual({
      header: { alg: 'EdDSA', typ: 'sd-jwt' },
      payload: { foo: 'bar' },
    });
  });

  test('custom verifier in config', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const testVerifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const SDJwtInstance = sdjwt.create({
      verifier: testVerifier,
    });

    const credential = await SDJwtInstance.issue(
      { foo: 'bar' },
      { privateKey },
    );

    const verified = await SDJwtInstance.verify(credential);

    expect(verified).toStrictEqual({
      header: { alg: 'EdDSA', typ: 'sd-jwt' },
      payload: { foo: 'bar' },
    });
  });
});
