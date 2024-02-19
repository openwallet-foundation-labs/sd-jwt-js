import {
  Uint8ArrayToBase64Url,
  Base64urlDecode,
  Base64urlEncode,
  SDJWTException,
} from '@hopae/sd-jwt-util';
import { HasherAndAlg } from '@hopae/sd-jwt-type';

export type DisclosureData<T> = [string, string, T] | [string, T];

export class Disclosure<T> {
  public salt: string;
  public key?: string;
  public value: T;
  private _digest: string | undefined;

  public constructor(data: DisclosureData<T>, digest?: string) {
    this._digest = digest;
    if (data.length === 2) {
      this.salt = data[0];
      this.value = data[1];
      return;
    }
    if (data.length === 3) {
      this.salt = data[0];
      this.key = data[1] as string;
      this.value = data[2];
      return;
    }
    throw new SDJWTException('Invalid disclosure data');
  }

  // We need to digest of the original encoded data.
  // After decode process, we use JSON.stringify to encode the data.
  // This can be different from the original encoded data.
  public static async fromEncode<T>(s: string, hash: HasherAndAlg) {
    const { hasher, alg } = hash;
    const digest = await hasher(s, alg);
    const digestStr = Uint8ArrayToBase64Url(digest);
    const item = JSON.parse(Base64urlDecode(s)) as DisclosureData<T>;
    return Disclosure.fromArray<T>(item, digestStr);
  }

  public static fromArray<T>(item: DisclosureData<T>, digest?: string) {
    return new Disclosure(item, digest);
  }

  public encode() {
    return Base64urlEncode(JSON.stringify(this.decode()));
  }

  public decode(): DisclosureData<T> {
    return this.key
      ? [this.salt, this.key, this.value]
      : [this.salt, this.value];
  }

  public async digest(hash: HasherAndAlg): Promise<string> {
    const { hasher, alg } = hash;
    if (!this._digest) {
      const hash = await hasher(this.encode(), alg);
      this._digest = Uint8ArrayToBase64Url(hash);
    }

    return this._digest;
  }
}
