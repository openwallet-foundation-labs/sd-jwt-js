import sdjwt, { DisclosureFrame } from '@hopae/sd-jwt';
import Crypto from 'node:crypto';

export const createKeyPair = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKey };
};

(async () => {
  const { privateKey, publicKey } = createKeyPair();
  // Define the claims object with the user's information
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };

  // Define the disclosure frame to specify which claims should be disclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'lastname', 'ssn'],
  };

  // Issue a signed JWT credential with the specified claims and disclosure frame
  // return a Encoded SD JWT.
  const credential = await sdjwt.issue(claims, privateKey, disclosureFrame);

  // Define the presentation frame to specify which claims should be presented
  const presentationFrame = ['firstname', 'ssn'];

  // Create a presentation using the issued credential and the presentation frame
  // return a Encoded SD JWT.
  const presentation = await sdjwt.present(credential, presentationFrame);

  // Define the required claims that need to be verified in the presentation
  const requiredClaims = ['firstname', 'ssn', 'id'];

  // Verify the presentation using the public key and the required claims
  // return a boolean result
  const verified = await sdjwt.verify(presentation, publicKey, requiredClaims);

  console.log(verified);
})();
