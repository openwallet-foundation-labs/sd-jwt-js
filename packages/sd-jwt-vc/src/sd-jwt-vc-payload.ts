import type { SdJwtPayload } from '@sd-jwt/core';

export interface SdJwtVcPayload extends SdJwtPayload {
  // The Issuer of the Verifiable Credential. The value of iss MUST be a URI. See [RFC7519] for more information.
  iss: string;
  // The time of issuance of the Verifiable Credential. See [RFC7519] for more information.
  iat: number;
  // OPTIONAL. The time before which the Verifiable Credential MUST NOT be accepted before validating. See [RFC7519] for more information.
  nbf?: number;
  //OPTIONAL. The expiry time of the Verifiable Credential after which the Verifiable Credential is no longer valid. See [RFC7519] for more information.
  exp?: number;
  // REQUIRED when Cryptographic Key Binding is to be supported. Contains the confirmation method as defined in [RFC7800]. It is RECOMMENDED that this contains a JWK as defined in Section 3.2 of [RFC7800]. For Cryptographic Key Binding, the Key Binding JWT in the Combined Format for Presentation MUST be signed by the key identified in this claim.
  cnf?: unknown;
  //REQUIRED. The type of the Verifiable Credential, e.g., https://credentials.example.com/identity_credential, as defined in Section 3.2.2.1.1.
  vct: string;
  // OPTIONAL. The information on how to read the status of the Verifiable Credential. See [I-D.looker-oauth-jwt-cwt-status-list] for more information.
  status?: unknown;

  //The identifier of the Subject of the Verifiable Credential. The Issuer MAY use it to provide the Subject identifier known by the Issuer. There is no requirement for a binding to exist between sub and cnf claims.
  sub?: string;
}
