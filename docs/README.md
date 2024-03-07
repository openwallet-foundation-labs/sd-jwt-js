## What is Selective Disclosure for JWTs?

Selective Disclosure for JWTs (JSON Web Tokens) is a concept aimed at enhancing privacy and data minimization in digital transactions. It allows the holder of a JWT to reveal only a subset of the information contained in the token, rather than disclosing the full contents.

You can check the details of the standard here: https://www.ietf.org/archive/id/draft-ietf-oauth-selective-disclosure-jwt-07.html

## What is SD-JWT-JS?

SD-JWT-JS is a [promise-based](https://javascript.info/promise-basics) SD JWT Client for [node.js](https://nodejs.org/) and the browser. It is [isomorphic](https://www.lullabot.com/articles/what-is-an-isomorphic-application) (= it can run in the browser and nodejs with the same codebase). On the server-side it uses the native [crypto](https://nodejs.org/api/crypto.html) module, while on the client (browser) it uses [broswer crypto module](https://developer.mozilla.org/en-US/docs/Web/API/Crypto).

## Features

- Issuer
  - Issue SD JWT Token
  - Add Key Binding in SD JWT Token
- Holder
  - Validate SD JWT Token
  - Selectively present SD JWT Token
- Verifier
  - Verify SD JWT Token
  - Verify Key Binding

## Installing

### If you want to use SD-JWT VC for credentials

Using npm:

```bash
npm install @sd-jwt/sd-jwt-vc
```

Using yarn:

```bash
yarn add @sd-jwt/sd-jwt-vc
```

Using pnpm:

```bash
pnpm install @sd-jwt/sd-jwt-vc
```

### Using SD JWT Features Only

Using npm:

```bash
npm install @sd-jwt/core
```

Using yarn:

```bash
yarn add @sd-jwt/core
```

Using pnpm:

```bash
pnpm install @sd-jwt/core
```

## Usage & Documentation

You can find the documentation and usage examples in the directory by versions

- [0.x documentation](0.x/README.md)
