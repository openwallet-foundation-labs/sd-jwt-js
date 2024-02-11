import { Base64 } from 'js-base64';

const encode = (input: string): string => Base64.encodeURI(input);

const decode = (input: string): string => {
  return Base64.decode(input);
};

export const Base64Url = {
  encode,
  decode,
};
