import sdjwt from './index';
import Crypto from 'node:crypto';
import { DisclosureFrame } from './type';

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
  const encodedSdjwt = await sdjwt.issue(claims, privateKey, disclosureFrame);
  console.log(encodedSdjwt);
  const validated = await sdjwt.validate(encodedSdjwt, publicKey);
  console.log(validated);

  const decoded = sdjwt.decode(encodedSdjwt);
  console.log({ keys: decoded.keys() }); // wip
  const payloads = decoded.getClaims(); // wip
  const keys = decoded.presentableKeys();
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
  const res = sdjwt.present(encodedSdjwt, presentationFrame);
  console.log(res);

  const requiredClaimKeys = ['firstname', 'id', 'data.ssn'];
  const verified = await sdjwt.verify(
    encodedSdjwt,
    publicKey,
    requiredClaimKeys,
  );
  console.log(verified);
})();
