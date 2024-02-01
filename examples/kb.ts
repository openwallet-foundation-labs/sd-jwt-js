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

  const kbPayload = {
    iat: Math.floor(Date.now() / 1000),
    aud: 'https://example.com',
    nonce: '1234',
    custom: 'data',
    sd_hash: '1234',
  };

  const encodedSdjwt = await sdjwt.issue(claims, privateKey, disclosureFrame, {
    kb: {
      alg: 'EdDSA',
      payload: kbPayload,
      privateKey,
    },
  });
  console.log('encodedSdjwt:', encodedSdjwt);
  const sdjwttoken = sdjwt.decode(encodedSdjwt);
  console.log(sdjwttoken);

  const presentedSdJwt = await sdjwt.present(encodedSdjwt, ['id']);

  const verified = await sdjwt.verify(
    presentedSdJwt,
    publicKey,
    ['id', 'ssn'],
    {
      kb: {
        publicKey,
      },
    },
  );
  console.log(verified);
})();
