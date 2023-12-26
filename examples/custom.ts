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
  // You can create a custom SDJwt instance with your own hasher and salt generator
  const SDJwtInstance = sdjwt.create({ hasher: digest, saltGenerator: salt });

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
  const credential = await SDJwtInstance.issue(
    claims,
    privateKey,
    disclosureFrame,
  );
  console.log('encodedJwt:', credential);

  // Holder Receive the credential from the issuer and validate it
  // Return a boolean result
  const validated = await SDJwtInstance.validate(credential, publicKey);
  console.log('validated:', validated);

  // You can decode the SD JWT to get the payload and the disclosures
  const sdJwtToken = SDJwtInstance.decode(credential);

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

  console.log(
    '================================================================',
  );

  // Holder Define the presentation frame to specify which claims should be presented
  // The list of presented claims must be a subset of the disclosed claims
  // the presentation frame is determined by the verifier or the protocol that was agreed upon between the holder and the verifier
  const presentationFrame = ['firstname', 'id'];

  // Create a presentation using the issued credential and the presentation frame
  // return a Encoded SD JWT. Holder send the presentation to the verifier
  const presentation = await SDJwtInstance.present(
    credential,
    presentationFrame,
  );
  console.log('presentedSDJwt:', presentation);

  // Verifier Define the required claims that need to be verified in the presentation
  const requiredClaims = ['firstname', 'id'];

  // Verify the presentation using the public key and the required claims
  // return a boolean result
  const verified = await SDJwtInstance.verify(
    presentation,
    publicKey,
    requiredClaims,
  );
  console.log('verified:', verified);
})();
