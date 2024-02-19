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

export const splitSdJwt = (
  sdjwt: string,
): { jwt: string; disclosures: string[]; kbJwt?: string } => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
  if (encodedDisclosures.length === 0) {
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

export const decodeSdJwt = async (
  sdjwt: string,
  hasher: Hasher,
): Promise<DecodedSDJwt> => {
  const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
  const jwt = decodeJwt(encodedJwt);

  if (encodedDisclosures.length === 0) {
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

export const getClaims = async <T>(
  rawPayload: any,
  disclosures: Array<Disclosure<any>>,
  hasher: Hasher,
): Promise<T> => {
  const { unpackedObj } = await unpack(rawPayload, disclosures, hasher);
  return unpackedObj as T;
};

export const unpackArray = (
  arr: Array<any>,
  map: Record<string, Disclosure<any>>,
  prefix: string = '',
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
  prefix: string = '',
): { unpackedObj: any; disclosureKeymap: Record<string, string> } => {
  const keys: Record<string, string> = {};
  if (obj instanceof Object) {
    if (obj instanceof Array) {
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
      _sd.forEach((hash: string) => {
        const disclosed = map[hash];
        if (disclosed && disclosed.key) {
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
      });
    }

    const unpackedObj = Object.assign(payload, claims);
    return { unpackedObj, disclosureKeymap: keys };
  }
  return { unpackedObj: obj, disclosureKeymap: keys };
};

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

export const getSDAlgAndPayload = (sdjwtPayload: any) => {
  const { _sd_alg, ...payload } = sdjwtPayload;
  if (typeof _sd_alg !== 'string') {
    // This is for compatibility
    return { _sd_alg: 'sha-256', payload };
  }
  return { _sd_alg, payload };
};

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

type DecodedSDJwt = {
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
