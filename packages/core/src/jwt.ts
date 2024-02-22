import { Base64urlEncode, SDJWTException } from '@sd-jwt/utils';
import { Base64urlString, Signer, Verifier } from '@sd-jwt/types';
import { decodeJwt } from '@sd-jwt/decode';

export type JwtData<
  Header extends Record<string, unknown>,
  Payload extends Record<string, unknown>,
> = {
  header?: Header;
  payload?: Payload;
  signature?: Base64urlString;
};

// This class is used to create and verify JWT
// Contains header, payload, and signature
export class Jwt<
  Header extends Record<string, unknown> = Record<string, unknown>,
  Payload extends Record<string, unknown> = Record<string, unknown>,
> {
  public header?: Header;
  public payload?: Payload;
  public signature?: Base64urlString;

  constructor(data?: JwtData<Header, Payload>) {
    this.header = data?.header;
    this.payload = data?.payload;
    this.signature = data?.signature;
  }

  public static decodeJWT<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
  >(
    jwt: string,
  ): { header: Header; payload: Payload; signature: Base64urlString } {
    return decodeJwt(jwt);
  }

  public static fromEncode<
    Header extends Record<string, unknown> = Record<string, unknown>,
    Payload extends Record<string, unknown> = Record<string, unknown>,
  >(encodedJwt: string): Jwt<Header, Payload> {
    const { header, payload, signature } = Jwt.decodeJWT<Header, Payload>(
      encodedJwt,
    );

    const jwt = new Jwt<Header, Payload>({
      header,
      payload,
      signature,
    });

    return jwt;
  }

  public setHeader(header: Header): Jwt<Header, Payload> {
    this.header = header;
    return this;
  }

  public setPayload(payload: Payload): Jwt<Header, Payload> {
    this.payload = payload;
    return this;
  }

  public async sign(signer: Signer) {
    if (!this.header || !this.payload) {
      throw new SDJWTException('Sign Error: Invalid JWT');
    }

    const header = Base64urlEncode(JSON.stringify(this.header));
    const payload = Base64urlEncode(JSON.stringify(this.payload));
    const data = `${header}.${payload}`;
    this.signature = await signer(data);

    return this.encodeJwt();
  }

  public encodeJwt(): string {
    if (!this.header || !this.payload || !this.signature) {
      throw new SDJWTException('Serialize Error: Invalid JWT');
    }

    const header = Base64urlEncode(JSON.stringify(this.header));
    const payload = Base64urlEncode(JSON.stringify(this.payload));
    const signature = this.signature;
    const compact = `${header}.${payload}.${signature}`;

    return compact;
  }

  public async verify(verifier: Verifier) {
    if (!this.header || !this.payload || !this.signature) {
      throw new SDJWTException('Verify Error: Invalid JWT');
    }

    const header = Base64urlEncode(JSON.stringify(this.header));
    const payload = Base64urlEncode(JSON.stringify(this.payload));
    const data = `${header}.${payload}`;

    const verified = verifier(data, this.signature);
    if (!verified) {
      throw new SDJWTException('Verify Error: Invalid JWT Signature');
    }
    return { payload: this.payload, header: this.header };
  }
}
