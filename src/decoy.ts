import { Base64Url } from './base64url';
import { generateSalt, digest , hexToB64Url} from './crypto';
import { Hasher, SaltGenerator } from './type';

export const createDecoy = async (
  hasher: Hasher = digest,
  saltGenerator: SaltGenerator = generateSalt,
): Promise<string> => {
  const salt = saltGenerator(16);
  const decoyHexString = await hasher(salt);
  const decoy = hexToB64Url(decoyHexString)
  return decoy;
};
