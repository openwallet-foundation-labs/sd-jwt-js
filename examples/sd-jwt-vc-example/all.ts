import { SDJwtVcInstance } from '@sd-jwt/sd-jwt-vc';
import { DisclosureFrame } from '@sd-jwt/types';
import { createSignerVerifier, digest, generateSalt } from './utils';

(async () => {
  const { signer, verifier } = await createSignerVerifier();

  // Create SDJwt instance for use
  const sdjwt = new SDJwtVcInstance({
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
    data: {
      firstname: 'John',
      lastname: 'Doe',
      ssn: '123-45-6789',
      list: [{ r: '1' }, 'b', 'c'],
    },
    data2: {
      hi: 'bye',
    },
  };

  // Issuer Define the disclosure frame to specify which claims can be disclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'id', 'data2'],
    data: {
      _sd: ['list'],
      _sd_decoy: 2,
      list: {
        _sd: [0, 2],
        _sd_decoy: 1,
        0: {
          _sd: ['r'],
        },
      },
    },
    data2: {
      _sd: ['hi'],
    },
  };

  // Issue a signed JWT credential with the specified claims and disclosures
  // Return a Encoded SD JWT. Issuer send the credential to the holder
  const credential = await sdjwt.issue(
    {
      iss: 'Issuer',
      iat: new Date().getTime(),
      vct: 'https://example.com',
      ...claims,
    },
    disclosureFrame,
  );
  console.log('encodedJwt:', credential);

  // Holder Receive the credential from the issuer and validate it
  // Return a result of header and payload
  const validated = await sdjwt.validate(credential);
  console.log('validated:', validated);

  // You can decode the SD JWT to get the payload and the disclosures
  const sdJwtToken = await sdjwt.decode(credential);

  // You can get the keys of the claims from the decoded SD JWT
  const keys = await sdJwtToken.keys(digest);
  console.log({ keys });

  // You can get the claims from the decoded SD JWT
  const payloads = await sdJwtToken.getClaims(digest);

  // You can get the presentable keys from the decoded SD JWT
  const presentableKeys = await sdJwtToken.presentableKeys(digest);

  console.log({
    payloads: JSON.stringify(payloads, null, 2),
    disclosures: JSON.stringify(sdJwtToken.disclosures, null, 2),
    claim: JSON.stringify(sdJwtToken.jwt?.payload, null, 2),
    presentableKeys,
  });

  console.log(
    '================================================================',
  );

  // Holder Define the presentation frame to specify which claims should be presented
  // The list of presented claims must be a subset of the disclosed claims
  // the presentation frame is determined by the verifier or the protocol that was agreed upon between the holder and the verifier
  const presentationFrame = { firstname: true, id: true };

  // Create a presentation using the issued credential and the presentation frame
  // return a Encoded SD JWT. Holder send the presentation to the verifier
  const presentation = await sdjwt.present(credential, presentationFrame);
  console.log('presentedSDJwt:', presentation);

  // Verifier Define the required claims that need to be verified in the presentation
  const requiredClaims = ['firstname', 'id', 'data.ssn'];

  // Verify the presentation using the public key and the required claims
  // return a boolean result
  const verified = await sdjwt.verify(credential, requiredClaims);
  console.log('verified:', verified);
})();
