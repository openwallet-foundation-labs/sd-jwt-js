import { Buffer } from 'node:buffer';

const textDecoder = new TextDecoder();

const toString = (input: string | Uint8Array): string => {
  if (input instanceof Uint8Array) {
    return textDecoder.decode(input);
  }
  return input;
};

const encode = (input: string | Uint8Array): string =>
  Buffer.from(toString(input)).toString('base64url');

const decode = (input: string | Uint8Array): string =>
  Buffer.from(toString(input), 'base64').toString();

export const Base64Url = {
  encode,
  decode,
};
