import Crypto from 'node:crypto';
import { SDJWTException } from './error';

export const generateSalt = (length: number): string => {
  if (length <= 0) {
    throw new SDJWTException('Salt length must be greater than 0.');
  }
  const saltBytes = Crypto.randomBytes(length);
  const salt = saltBytes.toString('hex');
  return salt;
};

export const random = (min: number, max: number): number => {
  if (min > max) {
    throw new SDJWTException(
      'Invalid range. The minimum value must be less than or equal to the maximum value.',
    );
  }
  const range = max - min + 1;
  const randomBytes = Crypto.randomBytes(4);
  const randomValue = randomBytes.readUInt32BE(0);
  const scaledRandom = randomValue % range;
  return min + scaledRandom;
};

export const hash = (data: string): string => {
  const hash = Crypto.createHash('sha256');
  hash.update(data);
  return hash.digest('hex');
};
