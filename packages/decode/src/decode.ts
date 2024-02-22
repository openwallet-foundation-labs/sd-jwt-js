import {
  Base64urlDecode,
  SDJWTException,
  Disclosure,
} from '@hopae/sd-jwt-util';
import {
  Hasher,
  HasherAndAlg,
  SD_DIGEST,
  SD_LIST_KEY,
  SD_SEPARATOR,
} from '@hopae/sd-jwt-type';
import { HasherAndAlgSync, HasherSync } from '@hopae/sd-jwt-type/src/type';

export const decodeJwt = <
  H extends Record<string, any>,
  T extends Record<string, any>,
>(
  jwt: string,
): { header: H; payload: T; signature: string } => {
  const { 0: header, 1: payload, 2: signature, length } = jwt.split('.');
  if (length !== 3) {
    throw new SDJWTException('Invalid JWT as input');
  }

  return {
    header: JSON.parse(Base64urlDecode(header)),
    payload: JSON.parse(Base64urlDecode(payload)),
    signature: signature,
  };
};

// Split the sdjwt into 3 parts: jwt, disclosures and keybinding jwt. each part is base64url encoded
// It's separated by the ~ character
//
// If there is no keybinding jwt, the third part will be undefined
// If there are no disclosures, the second part will be an empty array
export const splitSdJwt = (
  sdjwt: string,
): { jwt: string; disclosures: string[]; kbJwt?: string } => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
  if (encodedDisclosures.length === 0) {
    // if input is just jwt, then return here.
    // This is for compatibility with jwt
    return {
      jwt: encodedJwt,
      disclosures: [],
    };
  }

  const encodedKeyBindingJwt = encodedDisclosures.pop();
  return {
    jwt: encodedJwt,
    disclosures: encodedDisclosures,
    kbJwt: encodedKeyBindingJwt || undefined,
  };
};

// Decode the sdjwt into the jwt, disclosures and keybinding jwt
// jwt, disclosures and keybinding jwt are also decoded
export const decodeSdJwt = async (
  sdjwt: string,
  hasher: Hasher,
): Promise<DecodedSDJwt> => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
  const jwt = decodeJwt(encodedJwt);

  if (encodedDisclosures.length === 0) {
    // if input is just jwt, then return here.
    // This is for compatibility with jwt
    return {
      jwt,
      disclosures: [],
    };
  }

  const encodedKeyBindingJwt = encodedDisclosures.pop();
  const kbJwt = encodedKeyBindingJwt
    ? decodeJwt(encodedKeyBindingJwt)
    : undefined;

  const { _sd_alg } = getSDAlgAndPayload(jwt.payload);

  const disclosures = await Promise.all(
    encodedDisclosures.map((ed) =>
      Disclosure.fromEncode(ed, { alg: _sd_alg, hasher }),
    ),
  );

  return {
    jwt,
    disclosures,
    kbJwt,
  };
};

export const decodeSdJwtSync = (
  sdjwt: string,
  hasher: HasherSync,
): DecodedSDJwt => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
  const jwt = decodeJwt(encodedJwt);

  if (encodedDisclosures.length === 0) {
    // if input is just jwt, then return here.
    // This is for compatibility with jwt
    return {
      jwt,
      disclosures: [],
    };
  }

  const encodedKeyBindingJwt = encodedDisclosures.pop();
  const kbJwt = encodedKeyBindingJwt
    ? decodeJwt(encodedKeyBindingJwt)
    : undefined;

  const { _sd_alg } = getSDAlgAndPayload(jwt.payload);

  const disclosures = encodedDisclosures.map((ed) =>
    Disclosure.fromEncodeSync(ed, { alg: _sd_alg, hasher }),
  );

  return {
    jwt,
    disclosures,
    kbJwt,
  };
};

// Get the claims from jwt and disclosures
// The digested values are matched with the disclosures and the claims are extracted
export const getClaims = async <T>(
  rawPayload: any,
  disclosures: Array<Disclosure<any>>,
  hasher: Hasher,
): Promise<T> => {
  const { unpackedObj } = await unpack(rawPayload, disclosures, hasher);
  return unpackedObj as T;
};

export const getClaimsSync = <T>(
  rawPayload: any,
  disclosures: Array<Disclosure<any>>,
  hasher: HasherSync,
): T => {
  const { unpackedObj } = unpackSync(rawPayload, disclosures, hasher);
  return unpackedObj as T;
};

export const unpackArray = (
  arr: Array<any>,
  map: Record<string, Disclosure<any>>,
  prefix = '',
): { unpackedObj: any; disclosureKeymap: Record<string, string> } => {
  const keys: Record<string, string> = {};
  const unpackedArray: any[] = [];
  arr.forEach((item, idx) => {
    if (item instanceof Object) {
      if (item[SD_LIST_KEY]) {
        const hash = item[SD_LIST_KEY];
        const disclosed = map[hash];
        if (disclosed) {
          const presentKey = prefix ? `${prefix}.${idx}` : `${idx}`;
          keys[presentKey] = hash;

          const { unpackedObj, disclosureKeymap: disclosureKeys } = unpackObj(
            disclosed.value,
            map,
            presentKey,
          );
          unpackedArray.push(unpackedObj);
          Object.assign(keys, disclosureKeys);
        }
      } else {
        const newKey = prefix ? `${prefix}.${idx}` : `${idx}`;
        const { unpackedObj, disclosureKeymap: disclosureKeys } = unpackObj(
          item,
          map,
          newKey,
        );
        unpackedArray.push(unpackedObj);
        Object.assign(keys, disclosureKeys);
      }
    } else {
      unpackedArray.push(item);
    }
  });
  return { unpackedObj: unpackedArray, disclosureKeymap: keys };
};

export const unpackObj = (
  obj: any,
  map: Record<string, Disclosure<any>>,
  prefix = '',
): { unpackedObj: any; disclosureKeymap: Record<string, string> } => {
  const keys: Record<string, string> = {};
  if (obj instanceof Object) {
    if (Array.isArray(obj)) {
      return unpackArray(obj, map, prefix);
    }

    for (const key in obj) {
      if (
        key !== SD_DIGEST &&
        key !== SD_LIST_KEY &&
        obj[key] instanceof Object
      ) {
        const newKey = prefix ? `${prefix}.${key}` : key;
        const { unpackedObj, disclosureKeymap: disclosureKeys } = unpackObj(
          obj[key],
          map,
          newKey,
        );
        obj[key] = unpackedObj;
        Object.assign(keys, disclosureKeys);
      }
    }

    const { _sd, ...payload } = obj;
    const claims: any = {};
    if (_sd) {
      for (const hash of _sd) {
        const disclosed = map[hash];
        if (disclosed?.key) {
          const presentKey = prefix
            ? `${prefix}.${disclosed.key}`
            : disclosed.key;
          keys[presentKey] = hash;

          const { unpackedObj, disclosureKeymap: disclosureKeys } = unpackObj(
            disclosed.value,
            map,
            presentKey,
          );
          claims[disclosed.key] = unpackedObj;
          Object.assign(keys, disclosureKeys);
        }
      }
    }

    const unpackedObj = Object.assign(payload, claims);
    return { unpackedObj, disclosureKeymap: keys };
  }
  return { unpackedObj: obj, disclosureKeymap: keys };
};

// Creates a mapping of the digests of the disclosures to the actual disclosures
export const createHashMapping = async (
  disclosures: Array<Disclosure<any>>,
  hash: HasherAndAlg,
) => {
  const map: Record<string, Disclosure<any>> = {};
  for (let i = 0; i < disclosures.length; i++) {
    const disclosure = disclosures[i];
    const digest = await disclosure.digest(hash);
    map[digest] = disclosure;
  }
  return map;
};

export const createHashMappingSync = (
  disclosures: Array<Disclosure<any>>,
  hash: HasherAndAlgSync,
) => {
  const map: Record<string, Disclosure<any>> = {};
  for (let i = 0; i < disclosures.length; i++) {
    const disclosure = disclosures[i];
    const digest = disclosure.digestSync(hash);
    map[digest] = disclosure;
  }
  return map;
};

// Extract _sd_alg. If it is not present, it is assumed to be sha-256
export const getSDAlgAndPayload = (sdjwtPayload: any) => {
  const { _sd_alg, ...payload } = sdjwtPayload;
  if (typeof _sd_alg !== 'string') {
    // This is for compatibility
    return { _sd_alg: 'sha-256', payload };
  }
  return { _sd_alg, payload };
};

// Match the digests of the disclosures with the claims and extract the claims
// unpack function use unpackObj and unpackArray to recursively unpack the claims
export const unpack = async (
  sdjwtPayload: any,
  disclosures: Array<Disclosure<any>>,
  hasher: Hasher,
) => {
  const { _sd_alg, payload } = getSDAlgAndPayload(sdjwtPayload);
  const hash = { hasher, alg: _sd_alg };
  const map = await createHashMapping(disclosures, hash);

  return unpackObj(payload, map);
};

export const unpackSync = (
  sdjwtPayload: any,
  disclosures: Array<Disclosure<any>>,
  hasher: HasherSync,
) => {
  const { _sd_alg, payload } = getSDAlgAndPayload(sdjwtPayload);
  const hash = { hasher, alg: _sd_alg };
  const map = createHashMappingSync(disclosures, hash);

  return unpackObj(payload, map);
};

// This is the type of the object that is returned by the decodeSdJwt function
// It is a combination of the decoded jwt, the disclosures and the keybinding jwt
export type DecodedSDJwt = {
  jwt: {
    header: Record<string, any>;
    payload: Record<string, any>; // raw payload of sd-jwt
    signature: string;
  };
  disclosures: Array<Disclosure<any>>;
  kbJwt?: {
    header: Record<string, any>;
    payload: Record<string, any>;
    signature: string;
  };
};
