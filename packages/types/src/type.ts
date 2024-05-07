export const SD_SEPARATOR = '~';
export const SD_LIST_KEY = '...';
export const SD_DIGEST = '_sd';
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
  kbVerifier?: KbVerifier;
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

// This type declaration is from lib.dom.ts
interface RsaOtherPrimesInfo {
  d?: string;
  r?: string;
  t?: string;
}

interface JsonWebKey {
  alg?: string;
  crv?: string;
  d?: string;
  dp?: string;
  dq?: string;
  e?: string;
  ext?: boolean;
  k?: string;
  key_ops?: string[];
  kty?: string;
  n?: string;
  oth?: RsaOtherPrimesInfo[];
  p?: string;
  q?: string;
  qi?: string;
  use?: string;
  x?: string;
  y?: string;
}

export interface JwtPayload {
  cnf?: {
    jwk: JsonWebKey;
  };
  exp?: number;
  [key: string]: unknown;
}

export type OrPromise<T> = T | Promise<T>;

export type Signer = (data: string) => OrPromise<string>;
export type Verifier = (data: string, sig: string) => OrPromise<boolean>;
export type KbVerifier = (
  data: string,
  sig: string,
  payload: JwtPayload,
) => OrPromise<boolean>;
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

/**
 * This is a disclosureFrame type that is used to represent the structure of what is being disclosed.
 */
export type Extensible = Record<string, unknown | boolean>;

export type DisclosureFrame<T extends Extensible> = Frame<T>;

/**
 * This is a presentationFrame type that is used to represent the structure of what is being presented.
 * PresentationFrame is made from the payload type.
 * const claims = {
      firstname: 'John',
      lastname: 'Doe',
      ssn: '123-45-6789',
      id: '1234',
      data: {
        firstname: 'John',
        lastname: 'Doe',
        ssn: '123-45-6789',
        list: [{ r: 'd' }, 'b', 'c'],
        list2: ['1', '2', '3'],
        list3: ['1', null, 2],
      },
      data2: {
        hi: 'bye',
      },
    };

  Example of a presentationFrame:
  const presentationFrame: PresentationFrame<typeof claims> = {
    firstname: true,
    lastname: true,
    ssn: true,
    id: 'true',
    data: {
      firstname: true,
      list: {
        1: true,
        0: {
          r: true,
        },
      },
      list2: {
        1: true,
      },
      list3: true,
    },
    data2: true,
  };
*/
type PFrame<Payload> = Payload extends Array<infer U>
  ? U extends object
    ? Record<number, PFrame<U> | boolean> | boolean
    : Record<number, boolean> | boolean
  : {
      [K in keyof Payload]?: Payload[K] extends object
        ? PFrame<Payload[K]> | boolean
        : boolean;
    };

export type PresentationFrame<T extends Extensible> = PFrame<T>;
