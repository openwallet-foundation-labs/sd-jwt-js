import { Base64Url } from './base64url';
import { generateSalt, digest } from './crypto';
import { Hasher, SaltGenerator } from './type';

export const createDecoy = async (
  hasher: Hasher = digest,
  saltGenerator: SaltGenerator = generateSalt,
): Promise<string> => {
  const salt = saltGenerator(16);
  const digest = await hasher(salt);
  const decoy = Base64Url.encode(digest);
  return decoy;
};
