import { HasherAndAlg, SaltGenerator } from './type';
import { Base64Url } from './base64url';

export const createDecoy = async (
  hash: HasherAndAlg,
  saltGenerator: SaltGenerator,
): Promise<string> => {
  const { hasher, alg } = hash;
  const salt = await saltGenerator(16);
  const decoy = await hasher(salt, alg);
  return Base64Url.Uint8ArrayToBase64Url(decoy);
};
