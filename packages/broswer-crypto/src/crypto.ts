export const generateSalt = (length: number): string => {
  if (length <= 0) {
    return '';
  }

  const array = new Uint8Array(length);
  globalThis.crypto.getRandomValues(array);

  const salt = Array.from(array, (byte) =>
    byte.toString(16).padStart(2, '0'),
  ).join('');

  return salt;
};

export async function digest(
  data: string,
  algorithm: string = 'SHA-256',
): Promise<Uint8Array> {
  const { subtle } = globalThis.crypto;
  const ec = new TextEncoder();
  const digest = await subtle.digest(algorithm, ec.encode(data));
  return new Uint8Array(digest);
}

export const getHasher = (algorithm: string = 'SHA-256') => {
  return (data: string) => digest(data, algorithm);
};
