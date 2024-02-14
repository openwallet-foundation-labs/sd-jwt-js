import {
  Base64urlDecode,
  Base64urlEncode,
  Uint8ArrayToBase64Url,
} from '../base64url';

describe('Base64url', () => {
  const raw = 'abcdefghijklmnopqrstuvwxyz';
  const encoded = 'YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo';
  test('Encode', () => {
    expect(Base64urlEncode(raw)).toStrictEqual(encoded);
  });
  test('Decode', () => {
    expect(Base64urlDecode(encoded)).toStrictEqual(raw);
  });
  test('Encode and decode', () => {
    const str = 'hello world';
    expect(Base64urlDecode(Base64urlEncode(str))).toStrictEqual(str);
  });
  test('Uint8Array', () => {
    const str = 'hello world';
    const uint8 = new TextEncoder().encode(str);
    expect(Uint8ArrayToBase64Url(uint8)).toStrictEqual(Base64urlEncode(str));
  });
});
