import sdjwt from '../index';
import Crypto from 'node:crypto';

describe('index', () => {
  test('create', async () => {
    const SDJwtInstance = sdjwt.create({
      omitTyp: true,
    });
    expect(SDJwtInstance).toBeDefined();
  });

  test('issue kbJwt', async () => {
    const { privateKey } = Crypto.generateKeyPairSync('ed25519');
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      privateKey,
      {
        _sd: ['foo'],
      },
      {
        kb: {
          alg: 'EdDSA',
          payload: {
            _sd_hash: 'sha-256',
            aud: '1',
            iat: 1,
            nonce: '342',
          },
          privateKey,
        },
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
      privateKey,
      {
        _sd: ['foo'],
      },
      {
        kb: {
          alg: 'EdDSA',
          payload: {
            _sd_hash: 'sha-256',
            aud: '1',
            iat: 1,
            nonce: '342',
          },
          privateKey,
        },
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
});
