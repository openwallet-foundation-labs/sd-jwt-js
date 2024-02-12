import { DisclosureFrame, SDJwtInstance } from '@hopae/sd-jwt';
import { createSignerVerifier, digest, generateSalt } from './utils';

(async () => {
  const { signer, verifier } = createSignerVerifier();

  // Create SDJwt instance for use
  const sdjwt = new SDJwtInstance({
    signer,
    verifier,
    sign_alg: 'EdDSA',
    hasher: digest,
    hash_alg: 'SHA-256',
    saltGenerator: generateSalt,
  });
  // Issuer Define the claims object with the user's information
  const claims = {
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };

  // Issuer Define the disclosure frame to specify which claims can be disclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['id'],
    _sd_decoy: 1, // 1 decoy digest will be added in SD JWT
  };
  const credential = await sdjwt.issue(claims, disclosureFrame);
  console.log('encodedSdjwt:', credential);

  // You can check the decoy digest in the SD JWT by decoding it
  const sdJwtToken = await sdjwt.decode(credential);
  console.log(sdJwtToken);
})();
