import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import type { DisclosureFrame, Signer, Verifier } from '@sd-jwt/types';
import { describe, test, expect } from 'vitest';
import { SDJwtVcInstance } from '..';
import type { SdJwtVcPayload } from '../sd-jwt-vc-payload';
import Crypto from 'node:crypto';

const iss = 'ExampleIssuer';
const vct = 'https://example.com/schema/1';
const iat = new Date().getTime() / 1000;

const createSignerVerifier = () => {
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

describe('App', () => {
  test('Example', async () => {
    const { signer, verifier } = createSignerVerifier();
    const sdjwt = new SDJwtVcInstance({
      signer,
      signAlg: 'EdDSA',
      verifier,
      hasher: digest,
      hashAlg: 'SHA-256',
      saltGenerator: generateSalt,
    });

    const claims = {
      firstname: 'John',
    };
    const disclosureFrame = {
      _sd: ['firstname', 'iss'],
    };

    const expectedPayload: SdJwtVcPayload = { iat, iss, vct, ...claims };
    const encodedSdjwt = sdjwt.issue(
      expectedPayload,
      disclosureFrame as unknown as DisclosureFrame<SdJwtVcPayload>,
    );
    expect(encodedSdjwt).rejects.toThrowError();
  });
});
