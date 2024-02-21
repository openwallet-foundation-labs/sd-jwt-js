## Create new Instance of SDJwtInstance

You can create a new instance of sdjwt with a custom config.

```ts
import sdjwtInstance from '@sd-jwt/core';

const sdjwt = new SDJwtInstance({
  signer,
  verifier,
  signAlg: 'EdDSA',
  hasher: digest,
  hashAlg: 'SHA-256',
  saltGenerator: generateSalt,
});
```

You can change the instances config by using config method.

## Configurations

```ts
sdjwt.config({
  hasher: CustomHasher,
});
```

- The config type

```ts
type SDJWTConfig = {
  omitTyp?: boolean; // omit typ property in JWT header
  hasher?: Hasher; // hash function: (data: string) => Promise<string> or string;
  hashAlg?: string; // hash algorithm string (e.g. 'SHA-256')
  saltGenerator?: SaltGenerator; // salt generate function: (length: number) => string;
  signer?: Signer; // sign function: (data: string) => Promise<string> or string;
  signAlg?: string; // sign algorithm string (e.g. 'EdDSA')
  verifier?: Verifier; // verify function: (data: string, signature: string) => Promise<boolean> or boolean;
  kbSigner?: Signer; // optional key binding sign function
  kbSignAlg?: string; // optional key binding sign algorithm
  kbVerifier?: Verifier; // optional key binding verify function
};
```

## Methods

- issue(claims, privateKey[, disclosureFrame, options])
- present(encodedSDJwt[, presentationKeys])
- validate(encodedSDJwt, publicKey)
- verify(encodedSDJwt, publicKey[, requiredClaimKeys, options])
- config(config)
- encode(sdjwt)
- decode(encodedSDJwt)
- keys(encodedSDJwt)
- presentableKeys(encodedSDJwt)
- getClaims(encodedSDJwt)
