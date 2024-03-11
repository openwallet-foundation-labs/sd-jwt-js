import {
  type Hasher,
  type PresentationFrame,
  SD_SEPARATOR,
} from '@sd-jwt/types';
import type { Disclosure } from '@sd-jwt/utils';
import {
  createHashMapping,
  decodeSdJwt,
  getSDAlgAndPayload,
  splitSdJwt,
  unpack,
  createHashMappingSync,
  decodeSdJwtSync,
  unpackSync,
} from '@sd-jwt/decode';
import type { HasherSync } from '@sd-jwt/types/src/type';

// Presentable keys
// The presentable keys are the path of JSON object that are presentable in the SD JWT
// e.g. if the SD JWT has the following payload and set sd like this:
// {
//   "foo": "bar",  // sd
//   "arr": [       // sd
//     "1",         // sd
//     "2",
//     {
//       "a": "1"   // sd
//     }
//   ],
//   "test": {
//     "zzz": "xxx" // sd
//   }
// }
// The presentable keys are: ["arr", "arr.0", "arr.2.a", "foo", "test.zzz"]
export const presentableKeys = async (
  rawPayload: Record<string, unknown>,
  disclosures: Array<Disclosure>,
  hasher: Hasher,
): Promise<string[]> => {
  const { disclosureKeymap } = await unpack(rawPayload, disclosures, hasher);
  return Object.keys(disclosureKeymap).sort();
};

export const presentableKeysSync = (
  rawPayload: Record<string, unknown>,
  disclosures: Array<Disclosure>,
  hasher: HasherSync,
): string[] => {
  const { disclosureKeymap } = unpackSync(rawPayload, disclosures, hasher);
  return Object.keys(disclosureKeymap).sort();
};

export const present = async <T extends Record<string, unknown>>(
  sdJwt: string,
  presentFrame: PresentationFrame<T>,
  hasher: Hasher,
): Promise<string> => {
  const { jwt, kbJwt } = splitSdJwt(sdJwt);
  const {
    jwt: { payload },
    disclosures,
  } = await decodeSdJwt(sdJwt, hasher);

  const { _sd_alg: alg } = getSDAlgAndPayload(payload);
  const hash = { alg, hasher };
  const keys = transformPresentationFrame(presentFrame);

  // hashmap: <digest> => <disclosure>
  // to match the digest with the disclosure
  const hashmap = await createHashMapping(disclosures, hash);
  const { disclosureKeymap } = await unpack(payload, disclosures, hasher);
  const presentedDisclosures = keys
    .map((k) => hashmap[disclosureKeymap[k]])
    .filter((d) => d !== undefined);

  return [
    jwt,
    ...presentedDisclosures.map((d) => d.encode()),
    kbJwt ?? '',
  ].join(SD_SEPARATOR);
};

export const presentSync = <T extends Record<string, unknown>>(
  sdJwt: string,
  presentFrame: PresentationFrame<T>,
  hasher: HasherSync,
): string => {
  const { jwt, kbJwt } = splitSdJwt(sdJwt);
  const {
    jwt: { payload },
    disclosures,
  } = decodeSdJwtSync(sdJwt, hasher);

  const { _sd_alg: alg } = getSDAlgAndPayload(payload);
  const hash = { alg, hasher };
  const keys = transformPresentationFrame(presentFrame);

  // hashmap: <digest> => <disclosure>
  // to match the digest with the disclosure
  const hashmap = createHashMappingSync(disclosures, hash);
  const { disclosureKeymap } = unpackSync(payload, disclosures, hasher);

  const presentedDisclosures = keys
    .map((k) => hashmap[disclosureKeymap[k]])
    .filter((d) => d !== undefined);

  return [
    jwt,
    ...presentedDisclosures.map((d) => d.encode()),
    kbJwt ?? '',
  ].join(SD_SEPARATOR);
};

/**
 * Transform the object keys into an array of strings. We are not sorting the array in any way.
 * @param obj The object to transform
 * @param prefix The prefix to add to the keys
 * @returns
 */
export const transformPresentationFrame = <T extends object>(
  obj: PresentationFrame<T>,
  prefix = '',
): string[] => {
  return Object.entries(obj).reduce<string[]>((acc, [key, value]) => {
    const newPrefix = prefix ? `${prefix}.${key}` : key;
    if (typeof value === 'boolean') {
      // only add it, when it's true
      if (value) {
        acc.push(newPrefix);
      }
    } else {
      acc.push(
        newPrefix,
        ...transformPresentationFrame(value as PresentationFrame<T>, newPrefix),
      );
    }
    return acc;
  }, []);
};
