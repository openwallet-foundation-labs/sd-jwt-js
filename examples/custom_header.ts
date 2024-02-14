import { DisclosureFrame, SDJwtInstance } from '@hopae/sd-jwt';
import { createSignerVerifier, digest, generateSalt } from './utils';

(async () => {
  const { signer, verifier } = createSignerVerifier();

  // Create SDJwt instance for use
  const sdjwt = new SDJwtInstance({
    signer,
    verifier,
    signAlg: 'EdDSA',
    hasher: digest,
    hashAlg: 'SHA-256',
    saltGenerator: generateSalt,
  });

  // Issuer Define the claims object with the user's information
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };

  // Issuer Define the disclosure frame to specify which claims can be disclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'id'],
  };

  // Issue a signed JWT credential with the specified claims and disclosures
  // Return a Encoded SD JWT. Issuer send the credential to the holder
  const credential = await sdjwt.issue(claims, disclosureFrame, {
    header: { typ: 'vc+sd-jwt', custom: 'data' }, // You can add custom header data to the SD JWT
  });
  console.log('encodedSdjwt:', credential);

  // You can check the custom header data by decoding the SD JWT
  const sdJwtToken = await sdjwt.decode(credential);
  console.log(sdJwtToken);
})();
