import { generateSalt, hash } from './crypto';
import { SDJWTException } from './error';
import { Hasher, SaltGenerator } from './type';

export const createDecoy = (
  count: number,
  hasher: Hasher = hash,
  saltGenerator: SaltGenerator = generateSalt,
): string => {
  if (count <= 0) {
    throw new SDJWTException('Decoy count must be more than zero');
  }

  let decoy: string = saltGenerator(16);

  for (let i = 0; i < count; i++) {
    decoy = hasher(decoy);
  }

  return decoy;
};
