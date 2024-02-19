import { HasherAndAlg, SaltGenerator } from '@hopae/sd-jwt-type';
import { Uint8ArrayToBase64Url } from '@hopae/sd-jwt-util';

export const createDecoy = async (
  hash: HasherAndAlg,
  saltGenerator: SaltGenerator,
): Promise<string> => {
  const { hasher, alg } = hash;
  const salt = await saltGenerator(16);
  const decoy = await hasher(salt, alg);
  return Uint8ArrayToBase64Url(decoy);
};
