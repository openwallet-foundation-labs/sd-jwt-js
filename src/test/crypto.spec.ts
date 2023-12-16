import { digest, generateSalt } from '../crypto';

describe('Crypto', () => {
  test('Salt', () => {
    expect(generateSalt(16).length).toBe(32);
  });
  test('Salt Error', () => {
    expect(() => generateSalt(0)).toThrow();
  });
  test('Hash SHA-256', async () => {
    expect(await digest('df9sf67d0fsdf8')).toBe(
      '0d3363fd83fa29a955ac77a4cfb80ac99b05c5e59d4c90fcfd2e4696eaba0e22',
    );
  });
  test('Hash SHA-384', async () => {
    expect(await digest('df9sf67d0fsdf8', 'SHA-384')).toBe(
      'c196e2809b4e8ce198236d4b8e8eda6d4b6d68259dc7a47b2641f4f35f0624fc8374092e43997cdce9421403a1a654de',
    );
  });
  test('Hash SHA-512', async () => {
    expect(await digest('df9sf67d0fsdf8', 'SHA-512')).toBe(
      '71150fee573770bf6a2f4b2a7db8c0f5a80463d7441a8773b24e36ed9fdd810436e54d31cd9689d0a11bbfbb4a56bb70004e8f3c635f7a3ff0575a32d1849b84',
    );
  });
});
