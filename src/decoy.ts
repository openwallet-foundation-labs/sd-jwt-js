import { Base64Url } from './base64url';
import { generateSalt, hash } from './crypto';
import { Hasher, SaltGenerator } from './type';

export const createDecoy = (
  hasher: Hasher = hash,
  saltGenerator: SaltGenerator = generateSalt,
): string => {
  const salt = saltGenerator(16);
  const digest = hasher(salt);
  const decoy = Base64Url.encode(digest);
  return decoy;
};
