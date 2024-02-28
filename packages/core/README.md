![License](https://img.shields.io/github/license/openwallet-foundation-labs/sd-jwt-js.svg)
![NPM](https://img.shields.io/npm/v/%40sd-jwt%2Fcore)
![Release](https://img.shields.io/github/v/release/openwallet-foundation-labs/sd-jwt-js)
![Stars](https://img.shields.io/github/stars/openwallet-foundation-labs/sd-jwt-js)

# SD-JWT Implementation in JavaScript (TypeScript)

## SD-JWT Core

### About

Core library for selective disclosure JWTs

Check the detail description in our github [repo](https://github.com/openwallet-foundation-labs/sd-jwt-js).

### Installation

To install this project, run the following command:

```bash
# using npm
npm install @sd-jwt/core

# using yarn
yarn add @sd-jwt/core

# using pnpm
pnpm install @sd-jwt/core
```

Ensure you have Node.js installed as a prerequisite.

### Usage

The library can be used to create sd-jwt based credentials. To be compliant with the  `sd-jwt-vc` standard, you can use the `@sd-jwt/sd-jwt-vc` that is implementing this spec.
If you want to use the pure sd-jwt class or implement your own sd-jwt credential approach, you can use this library.

### Dependencies

- @sd-jwt/decode
- @sd-jwt/types
- @sd-jwt/utils
