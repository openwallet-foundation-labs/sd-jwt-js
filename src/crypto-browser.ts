import { SDJWTException } from './error';

export const generateSalt = (length: number): string => {
  if (length <= 0) {
    throw new SDJWTException('Salt length must be greater than 0.');
  }

  const array = new Uint8Array(length);
  globalThis.crypto.getRandomValues(array);

  const salt = Array.from(array, (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');

  return salt;
};

export async function digestBroswer(
  data: string,
  algorithm: string = 'SHA-256',
) {
  const { subtle } = globalThis.crypto;
  const ec = new TextEncoder();
  const digest = await subtle.digest(algorithm, ec.encode(data));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export async function digest(
  data: string,
  algorithm: string = 'SHA-256',
): Promise<string> {
  const { subtle } = globalThis.crypto;
  const ec = new TextEncoder();
  const digest = await subtle.digest(algorithm, ec.encode(data));
  return Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
}

export const getHasher = (algorithm: string = 'SHA-256') => {
  return (data: string) => digest(data, algorithm);
};
