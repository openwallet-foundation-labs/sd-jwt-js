import { Base64 } from 'js-base64';

export const Base64urlEncode = Base64.encodeURI;

export const Base64urlDecode = Base64.decode;

export const Uint8ArrayToBase64Url = (input: Uint8Array): string =>
  Base64.fromUint8Array(input, true);
