import { Signer, Verifier, SDJwtInstance } from '../index';
import Crypto from 'node:crypto';
import { digest, generateSalt } from './crypto.spec';

export const createSignerVerifier = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  const signer: Signer = async (data: string) => {
    const sig = Crypto.sign(null, Buffer.from(data), privateKey);
    return Buffer.from(sig).toString('base64url');
  };
  const verifier: Verifier = async (data: string, sig: string) => {
    return Crypto.verify(
      null,
      Buffer.from(data),
      publicKey,
      Buffer.from(sig, 'base64url'),
    );
  };
  return { signer, verifier };
};

describe('index', () => {
  test('create', async () => {
    const sdjwt = new SDJwtInstance();
    expect(sdjwt).toBeDefined();
  });

  test('kbJwt', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance({
      signer,
      sign_alg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kb_sign_alg: 'EdDSA',
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      {
        _sd: ['foo'],
      },
    );

    expect(credential).toBeDefined();

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
          sd_hash: 'sha-256',
          aud: '1',
          iat: 1,
          nonce: '342',
        },
      },
    });

    expect(presentation).toBeDefined();
  });

  test('issue', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance({
      signer,
      sign_alg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      {
        _sd: ['foo'],
      },
    );

    expect(credential).toBeDefined();
  });

  test('verify failed', async () => {
    const { signer } = createSignerVerifier();
    const { publicKey } = Crypto.generateKeyPairSync('ed25519');
    const failedverifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };

    const sdjwt = new SDJwtInstance({
      signer,
      sign_alg: 'EdDSA',
      verifier: failedverifier,
      hasher: digest,
      saltGenerator: generateSalt,
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      {
        _sd: ['foo'],
      },
    );

    try {
      await sdjwt.verify(credential);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('verify failed with kbJwt', async () => {
    const { signer, verifier } = createSignerVerifier();
    const { publicKey } = Crypto.generateKeyPairSync('ed25519');
    const failedverifier: Verifier = async (data: string, sig: string) => {
      return Crypto.verify(
        null,
        Buffer.from(data),
        publicKey,
        Buffer.from(sig, 'base64url'),
      );
    };
    const sdjwt = new SDJwtInstance({
      signer,
      sign_alg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kbVerifier: failedverifier,
      kb_sign_alg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
          sd_hash: '',
          aud: '1',
          iat: 1,
          nonce: '342',
        },
      },
    });

    try {
      await sdjwt.verify(presentation);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('verify with kbJwt', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance({
      signer,
      sign_alg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kbVerifier: verifier,
      kb_sign_alg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
          sd_hash: 'sha-256',
          aud: '1',
          iat: 1,
          nonce: '342',
        },
      },
    });

    const results = await sdjwt.verify(presentation, ['foo'], true);
    expect(results).toBeDefined();
  });

  test('Hasher not found', async () => {
    const sdjwt = new SDJwtInstance({});
    try {
      const credential = await sdjwt.issue(
        {
          foo: 'bar',
        },
        {
          _sd: ['foo'],
        },
      );

      expect(credential).toBeDefined();
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('SaltGenerator not found', async () => {
    const sdjwt = new SDJwtInstance({
      hasher: digest,
    });
    try {
      const credential = await sdjwt.issue(
        {
          foo: 'bar',
        },
        {
          _sd: ['foo'],
        },
      );

      expect(credential).toBeDefined();
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('Signer not found', async () => {
    const sdjwt = new SDJwtInstance({
      hasher: digest,
      saltGenerator: generateSalt,
    });
    try {
      const credential = await sdjwt.issue(
        {
          foo: 'bar',
        },
        {
          _sd: ['foo'],
        },
      );

      expect(credential).toBeDefined();
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('Verifier not found', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance({
      signer,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kbVerifier: verifier,
      sign_alg: 'EdDSA',
      kb_sign_alg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
          sd_hash: 'sha-256',
          aud: '1',
          iat: 1,
          nonce: '342',
        },
      },
    });
    try {
      const results = await sdjwt.verify(presentation, ['foo'], true);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('kbSigner not found', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbVerifier: verifier,
      sign_alg: 'EdDSA',
      kb_sign_alg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      {
        _sd: ['foo'],
      },
    );
    try {
      const presentation = await sdjwt.present(credential, ['foo'], {
        kb: {
          payload: {
            sd_hash: 'sha-256',
            aud: '1',
            iat: 1,
            nonce: '342',
          },
        },
      });
    } catch (e) {
      expect(e).toBeDefined();
    }
  });

  test('kbVerifier not found', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      sign_alg: 'EdDSA',
      kb_sign_alg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
          sd_hash: 'sha-256',
          aud: '1',
          iat: 1,
          nonce: '342',
        },
      },
    });
    try {
      const results = await sdjwt.verify(presentation, ['foo'], true);
    } catch (e) {
      expect(e).toBeDefined();
    }
  });
});
