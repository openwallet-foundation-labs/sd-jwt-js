import sdjwt, { Signer } from '../index';
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
      privateKey,
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
      privateKey,
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

  test('verify failed', async () => {
    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      privateKey,
      {
        _sd: ['foo'],
      },
    );

    try {
      await sdjwt.verify(
        credential,
        Crypto.generateKeyPairSync('ed25519').privateKey,
      );
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
      privateKey,
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
      await sdjwt.verify(presentation, publicKey);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });
});
