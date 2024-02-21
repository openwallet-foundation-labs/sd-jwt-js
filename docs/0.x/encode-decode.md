## Decode

You can decode SD JWT encoded credential to SDJwt Object.

```ts
// decoded variable is SDJwt Object
const decoded = sdjwt.decode(encodedSdjwt);

// You can access inside of SDJwt object
console.log(decoded.jwt, decoded.disclosures);
```

## Encode

You can encode SD JWT object instance to encoded credential

```ts
// encode SDJwt object to string
const encodedSdjwt = sdjwt.encode(decoded);
// return base64url string
```
