![License](https://img.shields.io/github/license/openwallet-foundation-labs/sd-jwt-js.svg)
![NPM](https://img.shields.io/npm/v/%40sd-jwt%2Fcore)
![Release](https://img.shields.io/github/v/release/openwallet-foundation-labs/sd-jwt-js)
![Stars](https://img.shields.io/github/stars/openwallet-foundation-labs/sd-jwt-js)

# SD-JWT Implementation in JavaScript (TypeScript)

## SD-JWT-VC

### About

SD-JWT-VC format based on the core functions

Check the detail description in our github [repo](https://github.com/openwallet-foundation-labs/sd-jwt-js).

### Installation

To install this project, run the following command:

```bash
# using npm
npm install @sd-jwt/sd-jwt-vc

# using yarn
yarn add @sd-jwt/sd-jwt-vc

# using pnpm
pnpm install @sd-jwt/sd-jwt-vc
```

Ensure you have Node.js installed as a prerequisite.

### Usage

Here's a basic example of how to use this library:

```jsx
import { DisclosureFrame } from '@sd-jwt/sd-jwt-vc';

// identifier of the issuer
const iss = "University";

// issuance time
const iat = new Date().getTime() / 1000;

//unique identifier of the schema
const vct = "University-Degree";

// Issuer defines the claims object with the user's information
const claims = {
  firstname: 'John',
  lastname: 'Doe',
  ssn: '123-45-6789',
  id: '1234',
};

// Issuer defines the disclosure frame to specify which claims can be disclosed/undisclosed
const disclosureFrame: DisclosureFrame<typeof claims> = {
  _sd: ['firstname', 'lastname', 'ssn'],
};

// Issuer issues a signed JWT credential with the specified claims and disclosure frame
// returns an encoded JWT
const credential = await sdjwt.issue({iss, iat, vct, ...claims}, disclosureFrame);

// Holder may validate the credential from the issuer
const valid = await sdjwt.validate(credential);

// Holder defines the presentation frame to specify which claims should be presented
// The list of presented claims must be a subset of the disclosed claims
const presentationFrame = ['firstname', 'ssn'];

// Holder creates a presentation using the issued credential and the presentation frame
// returns an encoded SD JWT.
const presentation = await sdjwt.present(credential, presentationFrame);

// Verifier can verify the presentation using the Issuer's public key
const verified = await sdjwt.verify(presentation);
```

Check out more details in our [documentation](https://github.com/openwallet-foundation-labs/sd-jwt-js/tree/next/docs) or [examples](https://github.com/openwallet-foundation-labs/sd-jwt-js/tree/next/examples)

### Dependencies

- @sd-jwt/core
- @sd-jwt/types
- @sd-jwt/utils
