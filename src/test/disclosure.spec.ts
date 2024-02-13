import { generateSalt, digest as hashHex } from '../crypto';
import { Disclosure, DisclosureData } from '../disclosure';
import { SDJWTException } from '../error';
import { Base64Url } from '../base64url';
import { describe, expect, test } from 'vitest';

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

  test('should return a digest after calling digest method', async () => {
    const givenData: DisclosureData<string> = [
      '2GLC42sKQveCfGfryNRN9w',
      'given_name',
      'John',
    ];
    const theDisclosure = new Disclosure(givenData);
    //
    // JSON.stringify() version
    // SHA-256 Hash : 8VHiz7qTXavxvpiTYDCSr_shkUO6qRcVXjkhEnt1os4
    // Disclosure: WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ
    // Contents: ["2GLC42sKQveCfGfryNRN9w","given_name","John"]
    //
    // Testing encoding of the data using encodeRaw and encode functions.
    // The differences in the output of encodeRaw and encode methods
    // arise from the formatting during JSON.stringify operation. encodeRaw retains whitespace while encode does not.
    expect(theDisclosure.encodeRaw(TestDataDraft7.claimTests[0].contents)).toBe(
      TestDataDraft7.claimTests[0].disclosure,
    );
    expect(theDisclosure.encode()).toBe(
      'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ',
    );

    //
    // Testing digestRaw function. Testing against known digest and disclosure pairs.
    // The digest is expected to be same as the known digest when passed with the corresponding disclosure.
    //
    await expect(
      theDisclosure.digestRaw(hashHex, TestDataDraft7.claimTests[0].disclosure),
    ).resolves.toBe(TestDataDraft7.claimTests[0].digest);
    await expect(
      theDisclosure.digestRaw(
        hashHex,
        'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ',
      ),
    ).resolves.toBe('8VHiz7qTXavxvpiTYDCSr_shkUO6qRcVXjkhEnt1os4');
    await expect(theDisclosure.digest(hashHex)).resolves.toBe(
      '8VHiz7qTXavxvpiTYDCSr_shkUO6qRcVXjkhEnt1os4',
    );
    //
    // The result of digestRaw changes based on the hashing strategy used. In this test, we are using the test data from 'draft-ietf-oauth-selective-disclosure-jwt-07'.
    //
    for (const elem of TestDataDraft7.sha256Tests) {
      await expect(
        theDisclosure.digestRaw(hashHex, elem.disclosure),
      ).resolves.toBe(elem.digest);
    }
  });
});
