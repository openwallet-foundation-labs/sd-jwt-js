import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { DisclosureFrame } from '@sd-jwt/types';
import { createSignerVerifier, digest, generateSalt } from './utils';

(async () => {
  const { signer, verifier } = await createSignerVerifier();

  // Create SDJwt instance for use
  const sdjwt = new SDJwtVcInstance({
    signer,
    signAlg: 'EdDSA',
    verifier,
    hasher: digest,
    saltGenerator: generateSalt,
    kbSigner: signer,
    kbSignAlg: 'EdDSA',
    kbVerifier: verifier,
  });
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'id'],
  };

  const kbPayload = {
    iat: Math.floor(Date.now() / 1000),
    aud: 'https://example.com',
    nonce: '1234',
    custom: 'data',
  };

  const encodedSdjwt = await sdjwt.issue(
    {
      iss: 'Issuer',
      iat: new Date().getTime(),
      vct: 'https://example.com',
      ...claims,
    },
    disclosureFrame,
  );
  console.log('encodedSdjwt:', encodedSdjwt);
  const sdjwttoken = await sdjwt.decode(encodedSdjwt);
  console.log(sdjwttoken);

  const presentedSdJwt = await sdjwt.present(
    encodedSdjwt,
    { id: true },
    {
      kb: {
        payload: kbPayload,
      },
    },
  );

  const verified = await sdjwt.verify(presentedSdJwt, ['id', 'ssn'], true);
  console.log(verified);
})();
