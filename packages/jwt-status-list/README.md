![License](https://img.shields.io/github/license/openwallet-foundation-labs/sd-jwt-js.svg)
![NPM](https://img.shields.io/npm/v/%40sd-jwt%2Fhash)
![Release](https://img.shields.io/github/v/release/openwallet-foundation-labs/sd-jwt-js)
![Stars](https://img.shields.io/github/stars/openwallet-foundation-labs/sd-jwt-js)

# JWT Status List

This implementation is based on the this [IETF draft](https://datatracker.ietf.org/doc/draft-ietf-oauth-status-list/)

This status list is an encoded bit string where the status can be represented by multiple bits. This library provides functions to create and read the status list from a JWT and also to verify the status of a specific entry.


## Installation

```bash
npm install jwt-status-list
```

## Usage

Creation of a JWT Status List:
```typescript
// pass the list as an array and the amount of bits per entry.
const list = new StatusList([1, 0, 1, 1, 1], 1);
const iss = 'https://example.com';
const payload: JWTPayload = {
    iss,
    sub: `${iss}/statuslist/1`,
    iat: new Date().getTime() / 1000,
};
const header: JWTHeaderParameters = { alg: 'ES256' };

const jwt = createUnsignedJWT(list, payload, header);

// Sign the JWT with the private key
const signedJwt = await jwt.sign(privateKey);

```

Interaction with a JWT Status List:
```typescript
//validation of the JWT is not provided by this library!!!

// jwt that includes the status list reference
const reference = getStatusListFromJWT(jwt);

// download the status list
const list = await fetch(reference.uri);

//TODO: validate that the list jwt is signed by the issuer and is not expired!!!

//extract the status list
const statusList = getListFromStatusListJWT(list);

//get the status of a specific entry
const status = statusList.getStatus(reference.idx);

// handle the status
```

## Development

Install the dependencies:

```bash
pnpm install
```

Run the tests:

```bash
pnpm test
```
