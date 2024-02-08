import { createDecoy } from '../decoy';
import { Base64Url } from '../base64url';
import { digest } from '../crypto';

describe('Decoy', () => {
  test('decoy', async () => {
    const decoyValue = await createDecoy();
    // base64url-encoded sha256 is a 43-octet URL safe string.
    expect(decoyValue.length).toBe(43);
  });

  // ref https://datatracker.ietf.org/doc/draft-ietf-oauth-selective-disclosure-jwt/07/
  //  *Claim email*:
  //  *  SHA-256 Hash: JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE
  //  *  Disclosure: WyI2SWo3dE0tYTVpVlBHYm9TNXRtdlZBIiwgImVtYWlsIiwgImpvaG5kb2VAZXhhbXBsZS5jb20iXQ
  //  *  Contents: ["6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com"]
  test('apply hasher and saltGenerator', async () => {
    const decoyValue = await createDecoy(
      digest,
      () => Base64Url.encode('["6Ij7tM-a5iVPGboS5tmvVA", "email", "johndoe@example.com"]'),
    );
    expect(decoyValue).toBe('JzYjH4svliH0R3PyEMfeZu6Jt69u5qehZo7F7EPYlSE');
  });

});
