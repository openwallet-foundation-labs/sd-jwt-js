import { Base64 } from 'js-base64';

const encode = (input: string): string => Base64.encodeURI(input);

const decode = (input: string): string => {
  return Base64.decode(input);
};

const Uint8ArrayToBase64Url = (input: Uint8Array): string =>
  Base64.fromUint8Array(input, true);

export const Base64Url = {
  encode,
  decode,
  Uint8ArrayToBase64Url,
};
