import { KeyLike } from 'jose';
import { SDJWTException } from './error';
import { Jwt } from './jwt';
import { kbHeader, kbPayload } from './type';

export class KBJwt<
  Header extends kbHeader = kbHeader,
  Payload extends kbPayload = kbPayload,
> extends Jwt<Header, Payload> {
  public async verify(publicKey: Uint8Array | KeyLike) {
    if (
      !this.header?.alg ||
      !this.header.typ ||
      !this.payload?.iat ||
      !this.payload?.aud ||
      !this.payload?.nonce ||
      !this.payload?._sd_hash
    ) {
      throw new SDJWTException('Invalid Key Binding Jwt');
    }
    return await super.verify(publicKey);
  }

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
