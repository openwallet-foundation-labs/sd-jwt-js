# SD JWT Core Examples

This directory contains examples of how to use the SD JWT(sd-jwt-js) library.

## How to run the examples

```bash
pnpm install
```

## Run the example

```bash
pnpm run {example_file_name}

# example
pnpm run all
```

### Example lists

- basic: Example of basic usage(issue, validate, present, verify) of SD JWT
- all: Example of issue, present and verify the comprehensive data.
- custom: Example of using custom hasher and salt generator for SD JWT
- custom_header: Example of using custom header for SD JWT
- sdjwtobject: Example of using SD JWT Object
- decoy: Example of adding decoy digest in SD JWT
- kb: key binding example in SD JWT
- decode: Decoding example of a SD JWT sample

### Variables In Examples

- claims: the user's information
- disclosureFrame: specify which claims should be disclosed
- credential: Issued Encoded SD JWT.
- validated: result of SD JWT validation
- presentationFrame: specify which claims should be presented
- presentation: Presented Encoded SD JWT.
- requiredClaims: specify which claims should be verified
- verified: result of verification
- sdJwtToken: SD JWT Token Object
- SDJwtInstance: SD JWT Instance

## More examples from tests

You can find more examples from [tests](../test).
