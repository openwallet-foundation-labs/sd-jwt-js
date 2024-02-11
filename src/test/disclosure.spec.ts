import { generateSalt, digest as hashHex } from '../crypto';
import { Disclosure } from '../disclosure';
import { SDJWTException } from '../error';

/* 
ref draft-ietf-oauth-selective-disclosure-jwt-07
Claim given_name:
SHA-256 Hash: jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4
Disclosure: WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd
Contents: ["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]
For example, the SHA-256 digest of the Disclosure
WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0 would be uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY.
The SHA-256 digest of the Disclosure
WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0 would be w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs.
*/
const TestDataDraft7 = {
  claimTests: [
    {
      contents: '["2GLC42sKQveCfGfryNRN9w", "given_name", "John"]',
      digest: 'jsu9yVulwQQlhFlM_3JlzMaSFzglhQG0DpfayQwLUK4',
      disclosure:
        'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwgImdpdmVuX25hbWUiLCAiSm9obiJd',
    },
  ],
  sha256Tests: [
    {
      digest: 'uutlBuYeMDyjLLTpf6Jxi7yNkEF35jdyWMn9U7b_RYY',
      disclosure: 'WyI2cU1RdlJMNWhhaiIsICJmYW1pbHlfbmFtZSIsICJNw7ZiaXVzIl0',
    },
    {
      digest: 'w0I8EKcdCtUPkGCNUrfwVp2xEgNjtoIDlOxc9-PlOhs',
      disclosure: 'WyJsa2x4RjVqTVlsR1RQVW92TU5JdkNBIiwgIkZSIl0',
    },
  ],
};

describe('Disclosure', () => {
  test('create object disclosure', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'name', 'James']);
    expect(disclosure).toBeDefined();
    expect(disclosure.key).toBe('name');
    expect(disclosure.value).toBe('James');
    expect(disclosure.salt).toBe(salt);
  });

  test('create array disclosure', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'US']);
    expect(disclosure).toBeDefined();
    expect(disclosure.key).toBe(undefined);
    expect(disclosure.value).toBe('US');
    expect(disclosure.salt).toBe(salt);
  });

  test('create disclosure error', async () => {
    const salt = generateSalt(16);
    const data: [string, string, string] = [salt, 'name', 'James'];
    data.push('any');
    expect(() => new Disclosure(data)).toThrow();
    try {
      new Disclosure(data);
    } catch (e: unknown) {
      const error = e as SDJWTException;
      expect(typeof error.getFullMessage()).toBe('string');
    }
  });

  test('encode disclosure', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'name', 'James']);
    const encodedDisclosure = disclosure.encode();
    expect(encodedDisclosure).toBeDefined();
    expect(typeof encodedDisclosure).toBe('string');
  });

  test('decode disclosure', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'name', 'James']);
    const encodedDisclosure = disclosure.encode();
    const newDisclosure = Disclosure.fromEncode(encodedDisclosure);

    expect(newDisclosure).toBeDefined();
    expect(newDisclosure.key).toBe('name');
    expect(newDisclosure.value).toBe('James');
    expect(newDisclosure.salt).toBe(salt);
  });

  test('digest disclosure', async () => {
    const salt = generateSalt(16);
    const disclosure = new Disclosure([salt, 'name', 'James']);
    const digest = await disclosure.digest(hashHex);
    expect(digest).toBeDefined();
    expect(typeof digest).toBe('string');
  });
});
