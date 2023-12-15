import sdjwt, { DisclosureFrame } from '@hopae/sd-jwt';
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

  const keys = await sdjwt.presentableKeys(encodedSdjwt);
  console.log('presentable keys:', keys);

  console.log(
    '================================================================',
  );

  const presentationFrame = ['firstname', 'id'];
  const presentedSDJwt = await sdjwt.present(encodedSdjwt, presentationFrame);
  console.log('presentedSDJwt:', presentedSDJwt);
})();
