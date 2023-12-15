import { base64url } from 'jose';

const encode = (input: string | Uint8Array): string => base64url.encode(input);

const decode = (input: string | Uint8Array): string => {
  return new TextDecoder().decode(base64url.decode(input));
};

export const Base64Url = {
  encode,
  decode,
};
