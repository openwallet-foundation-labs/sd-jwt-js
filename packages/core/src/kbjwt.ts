import { SDJWTException } from '@hopae/sd-jwt-util';
import { Jwt } from './jwt';
import { Verifier, kbHeader, kbPayload } from '@hopae/sd-jwt-type';

export class KBJwt<
  Header extends kbHeader = kbHeader,
  Payload extends kbPayload = kbPayload,
> extends Jwt<Header, Payload> {
  // Checking the validity of the key binding jwt
  public async verify(verifier: Verifier) {
    if (
      !this.header?.alg ||
      !this.header.typ ||
      !this.payload?.iat ||
      !this.payload?.aud ||
      !this.payload?.nonce ||
      // this is for backward compatibility with version 06
      !(
        this.payload?.sd_hash ||
        (this.payload as Record<string, unknown> | undefined)?._sd_hash
      )
    ) {
      throw new SDJWTException('Invalid Key Binding Jwt');
    }
    return await super.verify(verifier);
  }

  // This function is for creating KBJwt object for verify properly
  public static fromKBEncode<
    Header extends kbHeader = kbHeader,
    Payload extends kbPayload = kbPayload,
  >(encodedJwt: string): KBJwt<Header, Payload> {
    const { header, payload, signature } = Jwt.decodeJWT<Header, Payload>(
      encodedJwt,
    );

    const jwt = new KBJwt<Header, Payload>({
      header,
      payload,
      signature,
    });

    return jwt;
  }
}
