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
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };

  // Issuer Define the disclosure frame to specify which claims can be disclosed
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['id'],
    _sd_decoy: 1, // 1 decoy digest will be added in SD JWT
  };
  const credential = await sdjwt.issue(claims, { privateKey }, disclosureFrame);
  console.log('encodedSdjwt:', credential);

  // You can check the decoy digest in the SD JWT by decoding it
  const sdJwtToken = sdjwt.decode(credential);
  console.log(sdJwtToken);
})();
