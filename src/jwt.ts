import { Base64Url } from './base64url';
import { SDJWTException } from './error';
import * as jose from 'jose';

export type JwtData<
  Header extends Record<string, any>,
  Payload extends Record<string, any>,
> = {
  header?: Header;
  payload?: Payload;
  signature?: Uint8Array;
};

export class Jwt<
  Header extends Record<string, any> = Record<string, any>,
  Payload extends Record<string, any> = Record<string, any>,
> {
  public header?: Header;
  public payload?: Payload;
  public signature?: Uint8Array;

  constructor(data?: JwtData<Header, Payload>) {
    this.header = data?.header;
    this.payload = data?.payload;
    this.signature = data?.signature;
  }

  public static decodeJWT<
    Header extends Record<string, any> = Record<string, any>,
    Payload extends Record<string, any> = Record<string, any>,
  >(jwt: string): { header: Header; payload: Payload; signature: Uint8Array } {
    const { 0: header, 1: payload, 2: signature, length } = jwt.split('.');
    if (length !== 3) {
      throw new SDJWTException('Invalid JWT as input');
    }

    return {
      header: JSON.parse(Base64Url.decode(header)),
      payload: JSON.parse(Base64Url.decode(payload)),
      signature: Uint8Array.from(Buffer.from(signature, 'base64url')),
    };
  }

  public static fromEncode<
    Header extends Record<string, any> = Record<string, any>,
    Payload extends Record<string, any> = Record<string, any>,
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

  public async sign(privateKey: Uint8Array | jose.KeyLike) {
    if (!this.header || !this.payload) {
      throw new SDJWTException('Sign Error: Invalid JWT');
    }
    // @ts-ignore
    const header = this.header as jose.JWTHeaderParameters;
    const encodedJwt = await new jose.SignJWT(this.payload)
      .setProtectedHeader(header)
      .sign(privateKey);

    const { signature } = Jwt.decodeJWT(encodedJwt);
    this.signature = signature;
    return encodedJwt;
  }

  public encodeJwt(): string {
    if (!this.header || !this.payload || !this.signature) {
      throw new SDJWTException('Serialize Error: Invalid JWT');
    }

    const header = Base64Url.encode(JSON.stringify(this.header));
    const payload = Base64Url.encode(JSON.stringify(this.payload));
    const signature = Buffer.from(this.signature).toString('base64url');
    const compact = `${header}.${payload}.${signature}`;

    return compact;
  }

  public async verify(publicKey: Uint8Array | jose.KeyLike) {
    if (!this.header || !this.payload || !this.signature) {
      throw new SDJWTException('Verify Error: Invalid JWT');
    }

    const jwt = this.encodeJwt();
    try {
      await jose.jwtVerify(jwt, publicKey);
    } catch (e) {
      return false;
    }
    return true;
  }
}
