import { createDecoy } from '../decoy';
import { Base64Url } from '../base64url';
import { digest, generateSalt } from './crypto.spec';

const hash = {
  hasher: digest,
  alg: 'SHA256',
};

describe('Decoy', () => {
  test('decoy', async () => {
    const decoyValue = await createDecoy(hash, generateSalt);
    expect(decoyValue.length).toBe(43);
  });

  // ref https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/07/
  //  *Claim email*:
  //  *  SHA-256 Hash: JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE
  //  *  Disclosure: WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ
  //  *  Contents: ["6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com"]
  test('apply hasher and saltGenerator', async () => {
    const decoyValue = await createDecoy(hash, () =>
      Base64Url.encode(
        '["6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com"]',
      ),
    );
    expect(decoyValue).toBe('JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE');
  });
});
