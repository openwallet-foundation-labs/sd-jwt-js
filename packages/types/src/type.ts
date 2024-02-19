export const SD_SEPARATOR = '~';
export const SD_LIST_KEY = '...';
export const SD_DIGEST = '_sd';
export const SD_JWT_TYP = 'sd-jwt';
export const SD_DECOY = '_sd_decoy';
export const KB_JWT_TYP = 'kb+jwt';

export type SDJWTCompact = string;
export type Base64urlString = string;

export type DisclosureData<T> = [string, string, T] | [string, T];

export type SDJWTConfig = {
  omitTyp?: boolean;
  hasher?: Hasher;
  hashAlg?: string;
  saltGenerator?: SaltGenerator;
  signer?: Signer;
  signAlg?: string;
  verifier?: Verifier;
  kbSigner?: Signer;
  kbSignAlg?: string;
  kbVerifier?: Verifier;
};

export type kbHeader = { typ: 'kb+jwt'; alg: string };
export type kbPayload = {
  iat: number;
  aud: string;
  nonce: string;
  sd_hash: string;
};

export type KBOptions = {
  payload: kbPayload;
};

export type OrPromise<T> = T | Promise<T>;

export type Signer = (data: string) => OrPromise<string>;
export type Verifier = (data: string, sig: string) => OrPromise<boolean>;
export type Hasher = (data: string, alg: string) => OrPromise<Uint8Array>;
export type SaltGenerator = (length: number) => OrPromise<string>;
export type HasherAndAlg = {
  hasher: Hasher;
  alg: string;
};

type NonNever<T> = {
  [P in keyof T as T[P] extends never ? never : P]: T[P];
};

export type SD<Payload> = { [SD_DIGEST]?: Array<keyof Payload> };
export type DECOY = { [SD_DECOY]?: number };

type Frame<Payload> = Payload extends Array<infer U>
  ? U extends object
    ? Record<number, Frame<U>> & SD<Payload> & DECOY
    : SD<Payload> & DECOY
  : Payload extends Record<string, unknown>
  ? NonNever<
      {
        [K in keyof Payload]?: Payload[K] extends object
          ? Frame<Payload[K]>
          : never;
      } & SD<Payload> &
        DECOY
    >
  : SD<Payload> & DECOY;

export type DisclosureFrame<T extends object> = Frame<T>;
