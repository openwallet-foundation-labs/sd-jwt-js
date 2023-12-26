import sdjwt, { DisclosureFrame } from '@hopae/sd-jwt';
import Crypto from 'node:crypto';

export const createKeyPair = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKey };
};

(async () => {
  const { privateKey, publicKey } = createKeyPair();
  // Issuer Define the claims object with the user's information
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };

  // Issuer Define the disclosure frame to specify which claims can be disclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'lastname', 'ssn'],
  };

  // Issue a signed JWT credential with the specified claims and disclosures
  // Return a Encoded SD JWT. Issuer send the credential to the holder
  const credential = await sdjwt.issue(claims, privateKey, disclosureFrame);

  // Holder Receive the credential from the issuer and validate it
  // Return a boolean result
  const valid = await sdjwt.validate(credential, publicKey);

  // Holder Define the presentation frame to specify which claims should be presented
  // The list of presented claims must be a subset of the disclosed claims
  // the presentation frame is determined by the verifier or the protocol that was agreed upon between the holder and the verifier
  const presentationFrame = ['firstname', 'ssn'];

  // Create a presentation using the issued credential and the presentation frame
  // return a Encoded SD JWT. Holder send the presentation to the verifier
  const presentation = await sdjwt.present(credential, presentationFrame);

  // Verifier Define the required claims that need to be verified in the presentation
  const requiredClaims = ['firstname', 'ssn', 'id'];

  // Verify the presentation using the public key and the required claims
  // return a boolean result
  const verified = await sdjwt.verify(presentation, publicKey, requiredClaims);
  console.log(verified);
})();
