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
  payload: Omit<kbPayload, 'sd_hash'>;
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

// This functions are sync versions
export type SignerSync = (data: string) => string;
export type VerifierSync = (data: string, sig: string) => boolean;
export type HasherSync = (data: string, alg: string) => Uint8Array;
export type SaltGeneratorSync = (length: number) => string;
export type HasherAndAlgSync = {
  hasher: HasherSync;
  alg: string;
};

type NonNever<T> = {
  [P in keyof T as T[P] extends never ? never : P]: T[P];
};

export type SD<Payload> = { [SD_DIGEST]?: Array<keyof Payload> };
export type DECOY = { [SD_DECOY]?: number };

/**
 * This is a disclosureFrame type that is used to represent the structure of what is being disclosed.
 * DisclosureFrame is made from the payload type.
 *
 * For example, if the payload is
 * {
 *  foo: 'bar',
 *  test: {
 *   zzz: 'yyy',
 *  }
 *  arr: ['1', '2', {a: 'b'}]
 * }
 *
 * The disclosureFrame can be subset of:
 * {
 *  _sd: ["foo", "test", "arr"],
 *  test: {
 *    _sd: ["zzz"],
 *  },
 *  arr: {
 *    _sd: ["0", "1", "2"],
 *    "2": {
 *      _sd: ["a"],
 *    }
 *  }
 * }
 *
 * The disclosureFrame can be used with decoy.
 * Decoy can be used like this:
 * {
 *  ...
 *  _sd: ...
 *  _sd_decoy: 1 // number of decoy in this layer
 * }
 *
 */
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
