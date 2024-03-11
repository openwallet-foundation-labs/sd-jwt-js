You can make Key Binding JWT and verify it.

## Issue

Assume that you have SD-JWT from issuer like this.

```ts
const claims = {
  firstname: 'John',
  lastname: 'Doe',
  ssn: '123-45-6789',
  id: '1234',
};
const disclosureFrame: DisclosureFrame<typeof claims> = {
  _sd: ['firstname', 'id'],
};
const encodedSdjwt = await sdjwt.issue(claims, disclosureFrame);
```

## Key Binding

```ts
const kbPayload = {
  iat: Math.floor(Date.now() / 1000),
  aud: 'https://example.com',
  nonce: '1234',
  custom: 'data',
};
const presentedSdJwt = await sdjwt.present(
  encodedSdjwt,
  { id: true },
  {
    kb: {
      payload: kbPayload,
    },
  },
);
```

## Verify

```ts
const verified = await sdjwt.verify(presentedSdJwt, ['id', 'ssn'], true);
console.log(verified.kb); // key binding header and payload is in kb object
```
