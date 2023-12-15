import { Base64Url } from './base64url';
import { SDJWTException } from './error';
import { Hasher } from './type';

export type DisclosureData<T> = [string, string, T] | [string, T];

export class Disclosure<T> {
  public salt: string;
  public key?: string;
  public value: T;
  private _digest: string | undefined;

  public constructor(data: DisclosureData<T>) {
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

  public static fromEncode<T>(s: string) {
    const item = JSON.parse(Base64Url.decode(s)) as DisclosureData<T>;
    return Disclosure.fromArray<T>(item);
  }

  public static fromArray<T>(item: DisclosureData<T>) {
    return new Disclosure(item);
  }

  public encode() {
    return Base64Url.encode(JSON.stringify(this.decode()));
  }

  public decode(): DisclosureData<T> {
    return this.key
      ? [this.salt, this.key, this.value]
      : [this.salt, this.value];
  }

  public async digest(hasher: Hasher): Promise<string> {
    if (!this._digest) {
      const hash = await hasher(this.encode());
      this._digest = Base64Url.encode(hash);
    }

    return this._digest;
  }
}
