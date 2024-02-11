import { generateSalt, digest as hasher } from './crypto.spec';
import { Disclosure } from '../disclosure';
import { SDJWTException } from '../error';

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
    const digest = await disclosure.digest({ alg: 'SHA256', hasher });
    expect(digest).toBeDefined();
    expect(typeof digest).toBe('string');
  });

  test('digest disclosure #1', async () => {
    const disclosure = new Disclosure([
      '2GLC42sKQveCfGfryNRN9w',
      'given_name',
      'John',
    ]);
    const encode = disclosure.encode();
    expect(encode).toBe(
      'WyIyR0xDNDJzS1F2ZUNmR2ZyeU5STjl3IiwiZ2l2ZW5fbmFtZSIsIkpvaG4iXQ',
    );
    const digest = await disclosure.digest({ alg: 'SHA256', hasher });
    expect(digest).toBe('8VHiz7qTXavxvpiTYDCSr_shkUO6qRcVXjkhEnt1os4');
  });
});
