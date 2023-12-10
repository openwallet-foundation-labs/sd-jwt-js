import { Jwt } from './jwt';

export const SD_SEPARATOR = '~';
export const SD_LIST_KEY = '...';
export const SD_DIGEST = '_sd';
export const SD_JWT_TYP = 'sd+jwt';
export const SD_DECOY = '_sd_decoy';

export type SDJWTCompact = string;

export type SDJWTConfig = {
  omitDecoy?: boolean;
  omitTyp?: boolean;
  hasher?: (data: string) => string;
  saltGenerator?: (length: number) => string;
};

export type kbHeader = { typ: string; alg: string };
export type kbPayload = {
  iat: string;
  aud: string;
  nonce: string;
  _sd_hash: string;
};

export type KeyBinding = Jwt<kbHeader, kbPayload>;

export type OrPromise<T> = T | Promise<T>;

export type Signer = (data: string) => OrPromise<Uint8Array>;
export type Verifier = (data: string, sig: Uint8Array) => OrPromise<boolean>;
export type Hasher = (data: string) => string;
export type SaltGenerator = (length: number) => string;

type NonNever<T> = {
  [P in keyof T as T[P] extends never ? never : P]: T[P];
};

export type SD<Payload> = { [SD_DIGEST]?: Array<keyof Payload> };
export type DECOY = { [SD_DECOY]?: number };

type BaseFrame<Payload> = Payload extends Array<infer U>
  ? U extends object
    ? Record<number, BaseFrame<U>> & SD<Payload> & DECOY
    : SD<Payload> & DECOY
  : Payload extends Record<string, unknown>
  ? NonNever<
      {
        [K in keyof Payload]?: Payload[K] extends object
          ? BaseFrame<Payload[K]>
          : never;
      } & SD<Payload> &
        DECOY
    >
  : SD<Payload> & DECOY;

export type DisclosureFrame<T> = BaseFrame<T>;
