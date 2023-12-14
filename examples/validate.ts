import sdjwt, { DisclosureFrame } from 'sd-jwt-js';
import Crypto from 'node:crypto';

export const createKeyPair = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKey };
};

(async () => {
  const { privateKey, publicKey } = createKeyPair();
  const claims = {
    firstname: 'John',
    lastname: 'Doe',
    ssn: '123-45-6789',
    id: '1234',
  };
  const disclosureFrame: DisclosureFrame<typeof claims> = {
    _sd: ['firstname', 'id'],
  };
  const encodedSdjwt = await sdjwt.issue(claims, privateKey, disclosureFrame);
  const validated = await sdjwt.validate(encodedSdjwt, publicKey);
  console.log('valiated:', validated);
})();
