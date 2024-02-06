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
    _sd: ['firstname', 'id'],
  };

  // Issue a signed JWT credential with the specified claims and disclosures
  // Return a Encoded SD JWT. Issuer send the credential to the holder
  const credential = await sdjwt.issue(claims, { privateKey }, disclosureFrame);
  console.log('encodedSdjwt:', credential);

  // You can decode the SD JWT to get the payload and the disclosures
  const sdJwtToken = sdjwt.decode(credential);
  console.log(sdJwtToken);

  // You can get the keys of the claims from the decoded SD JWT
  const keys = await sdJwtToken.keys();
  console.log({ keys });

  // You can get the claims from the decoded SD JWT
  const payloads = await sdJwtToken.getClaims();

  // You can get the presentable keys from the decoded SD JWT
  const presentableKeys = await sdJwtToken.presentableKeys();

  console.log({
    payloads: JSON.stringify(payloads, null, 2),
    disclosures: JSON.stringify(sdJwtToken.disclosures, null, 2),
    claim: JSON.stringify(sdJwtToken.jwt?.payload, null, 2),
    presentableKeys,
  });
})();
