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
  console.log('encodedJwt:', encodedSdjwt);
  const validated = await sdjwt.validate(encodedSdjwt, publicKey);
  console.log('validated:', validated);

  const decoded = sdjwt.decode(encodedSdjwt);
  console.log({ keys: await decoded.keys() });
  const payloads = await decoded.getClaims();
  const keys = await decoded.presentableKeys();
  console.log({
    payloads: JSON.stringify(payloads, null, 2),
    disclosures: JSON.stringify(decoded.disclosures, null, 2),
    claim: JSON.stringify(decoded.jwt?.payload, null, 2),
    keys,
  });

  console.log(
    '================================================================',
  );

  const presentationFrame = ['firstname', 'id'];
  const presentedSDJwt = await sdjwt.present(encodedSdjwt, presentationFrame);
  console.log('presentedSDJwt:', presentedSDJwt);

  const requiredClaimKeys = ['firstname', 'id'];
  const verified = await sdjwt.verify(
    encodedSdjwt,
    publicKey,
    requiredClaimKeys,
  );
  console.log('verified:', verified);
})();
