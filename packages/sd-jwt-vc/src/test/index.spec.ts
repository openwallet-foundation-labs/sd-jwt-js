import { digest, generateSalt } from '@sd-jwt/crypto-nodejs';
import type { DisclosureFrame } from '@sd-jwt/types';
import { describe, test, expect } from 'vitest';
import { SDJwtVcInstance } from '..';
import { createSignerVerifier } from '../../test/app-e2e.spec';
import type { SdJwtVcPayload } from '../sd-jwt-vc-payload';

const iss = 'ExampleIssuer';
const vct = 'https://example.com/schema/1';
const iat = new Date().getTime() / 1000;

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
