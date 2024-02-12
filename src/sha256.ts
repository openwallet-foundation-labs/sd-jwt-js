import { sha256 as nobleSha256 } from '@noble/hashes/sha256';

export const sha256 = (text: string): Uint8Array => {
  const uint8Array = new Uint8Array(text.length);

  for (let i = 0; i < text.length; i++) {
    uint8Array[i] = text.charCodeAt(i);
  }
  const hashBytes = nobleSha256(uint8Array);
  return hashBytes;
};
