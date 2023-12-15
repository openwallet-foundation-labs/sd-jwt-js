import sdjwt, { DisclosureFrame } from '@hopae/sd-jwt';
import Crypto from 'node:crypto';

export const salt = (length: number): string => {
  const saltBytes = Crypto.randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt;
};

export const digest = async (
  data: string,
  algorithm: string = 'SHA-256',
): Promise<string> => {
  const hash = Crypto.createHash(algorithm);
  hash.update(data);
  return hash.digest('hex');
};

export const createKeyPair = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKey };
};

(async () => {
  const SDJwtInstance = sdjwt.create({ hasher: digest, saltGenerator: salt });

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
  const encodedSdjwt = await SDJwtInstance.issue(
    claims,
    privateKey,
    disclosureFrame,
  );
  console.log('encodedJwt:', encodedSdjwt);
  const validated = await SDJwtInstance.validate(encodedSdjwt, publicKey);
  console.log('validated:', validated);

  const decoded = SDJwtInstance.decode(encodedSdjwt);
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
  const presentedSDJwt = await SDJwtInstance.present(
    encodedSdjwt,
    presentationFrame,
  );
  console.log('presentedSDJwt:', presentedSDJwt);

  const requiredClaimKeys = ['firstname', 'id'];
  const verified = await SDJwtInstance.verify(
    encodedSdjwt,
    publicKey,
    requiredClaimKeys,
  );
  console.log('verified:', verified);
})();
