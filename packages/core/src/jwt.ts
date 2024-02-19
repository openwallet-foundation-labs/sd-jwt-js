import {
  Base64urlDecode,
  Base64urlEncode,
  SDJWTException,
} from '@hopae/sd-jwt-util';
import { Base64urlString, Signer, Verifier } from './type';

export type JwtData<
  Header extends Record<string, any>,
  Payload extends Record<string, any>,
> = {
  header?: Header;
  payload?: Payload;
  signature?: Base64urlString;
};

export class Jwt<
  Header extends Record<string, any> = Record<string, any>,
  Payload extends Record<string, any> = Record<string, any>,
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
    Header extends Record<string, any> = Record<string, any>,
    Payload extends Record<string, any> = Record<string, any>,
  >(
    jwt: string,
  ): { header: Header; payload: Payload; signature: Base64urlString } {
    const { 0: header, 1: payload, 2: signature, length } = jwt.split('.');
    if (length !== 3) {
      throw new SDJWTException('Invalid JWT as input');
    }

    return {
      header: JSON.parse(Base64urlDecode(header)),
      payload: JSON.parse(Base64urlDecode(payload)),
      signature: signature,
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
