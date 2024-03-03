import { SDJwtInstance, SdJwtPayload } from '../index';
import { Signer, Verifier } from '@sd-jwt/types';
import Crypto, { KeyLike } from 'node:crypto';
import { describe, expect, test } from 'vitest';
import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import { KbVerifier, JwtPayload } from '@sd-jwt/types';
import { importJWK, exportJWK, JWK } from 'jose';

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
    const sdjwt = new SDJwtInstance<SdJwtPayload>();
    expect(sdjwt).toBeDefined();
  });

  test('kbJwt', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kbSignAlg: 'EdDSA',
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    expect(credential).toBeDefined();

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
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
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
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

    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier: failedverifier,
      hasher: digest,
      saltGenerator: generateSalt,
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
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
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kbVerifier: failedverifier,
      kbSignAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
          aud: '',
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

    const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');

    //TODO: maybe we can pass a minial class of the jwt to pass the token
    const kbVerifier: KbVerifier = async (
      data: string,
      sig: string,
      payload: JwtPayload,
    ) => {
      let publicKey: JsonWebKey;
      if (payload.cnf) {
        // use the key from the cnf
        publicKey = payload.cnf.jwk;
      } else {
        throw Error('key binding not supported');
      }
      // get the key of the holder to verify the signature
      return Crypto.verify(
        null,
        Buffer.from(data),
        (await importJWK(publicKey as JWK, 'EdDSA')) as KeyLike,
        Buffer.from(sig, 'base64url'),
      );
    };

    const kbSigner = (data: string) => {
      const sig = Crypto.sign(null, Buffer.from(data), privateKey);
      return Buffer.from(sig).toString('base64url');
    };

    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: kbSigner,
      kbVerifier: kbVerifier,
      kbSignAlg: 'EdDSA',
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iat: new Date().getTime(),
        cnf: {
          jwk: await exportJWK(publicKey),
        },
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
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
    const sdjwt = new SDJwtInstance<SdJwtPayload>({});
    try {
      const credential = await sdjwt.issue(
        {
          foo: 'bar',
          iss: 'Issuer',
          iat: new Date().getTime(),
          vct: '',
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
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      hasher: digest,
    });
    try {
      const credential = await sdjwt.issue(
        {
          foo: 'bar',
          iss: 'Issuer',
          iat: new Date().getTime(),
          vct: '',
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
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      hasher: digest,
      saltGenerator: generateSalt,
    });
    try {
      const credential = await sdjwt.issue(
        {
          foo: 'bar',
          iss: 'Issuer',
          iat: new Date().getTime(),
          vct: '',
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
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      kbVerifier: verifier,
      signAlg: 'EdDSA',
      kbSignAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
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
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbVerifier: verifier,
      signAlg: 'EdDSA',
      kbSignAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );
    try {
      const presentation = await sdjwt.present(credential, ['foo'], {
        kb: {
          payload: {
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
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      signAlg: 'EdDSA',
      kbSignAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
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

  test('kbSignAlg not found', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      verifier,
      hasher: digest,
      saltGenerator: generateSalt,
      kbSigner: signer,
      signAlg: 'EdDSA',
    });

    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = sdjwt.present(credential, ['foo'], {
      kb: {
        payload: {
          aud: '1',
          iat: 1,
          nonce: '342',
        },
      },
    });
    expect(presentation).rejects.toThrow(
      'Key Binding sign algorithm not specified',
    );
  });

  test('hasher is not found', async () => {
    const { signer } = createSignerVerifier();
    const sdjwt_create = new SDJwtInstance<SdJwtPayload>({
      signer,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    });
    const credential = await sdjwt_create.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );
    const sdjwt = new SDJwtInstance<SdJwtPayload>({});
    expect(sdjwt.keys('')).rejects.toThrow('Hasher not found');
    expect(sdjwt.presentableKeys('')).rejects.toThrow('Hasher not found');
    expect(sdjwt.getClaims('')).rejects.toThrow('Hasher not found');
    expect(() => sdjwt.decode('')).toThrowError('Hasher not found');
    expect(sdjwt.present(credential, ['foo'])).rejects.toThrow(
      'Hasher not found',
    );
  });

  test('presentableKeys', async () => {
    const { signer } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );
    const keys = await sdjwt.presentableKeys(credential);
    expect(keys).toBeDefined();
    expect(keys).toEqual(['foo']);
  });

  test('present all disclosures with kb jwt', async () => {
    const { signer } = createSignerVerifier();
    const sdjwt = new SDJwtInstance<SdJwtPayload>({
      signer,
      kbSigner: signer,
      hasher: digest,
      saltGenerator: generateSalt,
      signAlg: 'EdDSA',
      kbSignAlg: 'EdDSA',
    });
    const credential = await sdjwt.issue(
      {
        foo: 'bar',
        iss: 'Issuer',
        iat: new Date().getTime(),
        vct: '',
      },
      {
        _sd: ['foo'],
      },
    );

    const presentation = await sdjwt.present(credential, undefined, {
      kb: {
        payload: {
          aud: '1',
          iat: 1,
          nonce: '342',
        },
      },
    });

    const decoded = await sdjwt.decode(presentation);
    expect(decoded.jwt).toBeDefined();
    expect(decoded.disclosures).toBeDefined();
    expect(decoded.kbJwt).toBeDefined();
  });
});
