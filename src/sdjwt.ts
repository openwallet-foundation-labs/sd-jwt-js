import { createDecoy } from './decoy';
import { Disclosure } from './disclosure';
import { SDJWTException } from './error';
import { Jwt } from './jwt';
import { KBJwt } from './kbjwt';
import {
  DisclosureFrame,
  Hasher,
  HasherAndAlg,
  SDJWTCompact,
  SD_DECOY,
  SD_DIGEST,
  SD_LIST_KEY,
  SD_SEPARATOR,
  SaltGenerator,
  kbHeader,
  kbPayload,
} from './type';

export type SDJwtData<
  Header extends Record<string, any>,
  Payload extends Record<string, any>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> = {
  jwt?: Jwt<Header, Payload>;
  disclosures?: Array<Disclosure<any>>;
  kbJwt?: KBJwt<KBHeader, KBPayload>;
};

export class SDJwt<
  Header extends Record<string, any> = Record<string, any>,
  Payload extends Record<string, any> = Record<string, any>,
  KBHeader extends kbHeader = kbHeader,
  KBPayload extends kbPayload = kbPayload,
> {
  public jwt?: Jwt<Header, Payload>;
  public disclosures?: Array<Disclosure<any>>;
  public kbJwt?: KBJwt<KBHeader, KBPayload>;

  constructor(data?: SDJwtData<Header, Payload, KBHeader, KBPayload>) {
    this.jwt = data?.jwt;
    this.disclosures = data?.disclosures;
    this.kbJwt = data?.kbJwt;
  }

  public static async decodeSDJwt<
    Header extends Record<string, any> = Record<string, any>,
    Payload extends Record<string, any> = Record<string, any>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    sdjwt: SDJWTCompact,
    hasher: Hasher,
  ): Promise<{
    jwt: Jwt<Header, Payload>;
    disclosures: Array<Disclosure<any>>;
    kbJwt?: KBJwt<KBHeader, KBPayload>;
  }> {
    const [encodedJwt, ...encodedDisclosures] = sdjwt.split(SD_SEPARATOR);
    const jwt = Jwt.fromEncode<Header, Payload>(encodedJwt);

    if (encodedDisclosures.length === 0) {
      return {
        jwt,
        disclosures: [],
      };
    }

    const encodedKeyBindingJwt = encodedDisclosures.pop();
    const kbJwt = encodedKeyBindingJwt
      ? KBJwt.fromKBEncode<KBHeader, KBPayload>(encodedKeyBindingJwt)
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
  }

  public static async fromEncode<
    Header extends Record<string, any> = Record<string, any>,
    Payload extends Record<string, any> = Record<string, any>,
    KBHeader extends kbHeader = kbHeader,
    KBPayload extends kbPayload = kbPayload,
  >(
    encodedSdJwt: SDJWTCompact,
    hasher: Hasher,
  ): Promise<SDJwt<Header, Payload>> {
    const { jwt, disclosures, kbJwt } = await SDJwt.decodeSDJwt<
      Header,
      Payload,
      KBHeader,
      KBPayload
    >(encodedSdJwt, hasher);

    return new SDJwt<Header, Payload, KBHeader, KBPayload>({
      jwt,
      disclosures,
      kbJwt,
    });
  }

  public async present(keys: string[], hasher: Hasher): Promise<SDJWTCompact> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SDJWTException('Invalid sd-jwt: jwt or disclosures is missing');
    }
    const { _sd_alg: alg } = getSDAlgAndPayload(this.jwt.payload);
    const hash = { alg, hasher };
    const hashmap = await createHashMapping(this.disclosures, hash);
    const { disclosureKeymap } = await unpack(
      this.jwt.payload,
      this.disclosures,
      hasher,
    );

    const presentableKeys = Object.keys(disclosureKeymap);
    const missingKeys = keys.filter((k) => !presentableKeys.includes(k));
    if (missingKeys.length > 0) {
      throw new SDJWTException(
        `Invalid sd-jwt: invalid present keys: ${missingKeys.join(', ')}`,
      );
    }

    const disclosures = keys.map((k) => hashmap[disclosureKeymap[k]]);
    const presentSDJwt = new SDJwt({
      jwt: this.jwt,
      disclosures,
      kbJwt: this.kbJwt,
    });
    return presentSDJwt.encodeSDJwt();
  }

  public encodeSDJwt(): SDJWTCompact {
    const data: string[] = [];

    if (!this.jwt) {
      throw new SDJWTException('Invalid sd-jwt: jwt is missing');
    }

    const encodedJwt = this.jwt.encodeJwt();
    data.push(encodedJwt);

    if (this.disclosures && this.disclosures.length > 0) {
      const encodeddisclosures = this.disclosures
        .map((dc) => dc.encode())
        .join(SD_SEPARATOR);
      data.push(encodeddisclosures);
    }

    data.push(this.kbJwt ? this.kbJwt.encodeJwt() : '');
    return data.join(SD_SEPARATOR);
  }

  public async keys(hasher: Hasher): Promise<string[]> {
    return listKeys(await this.getClaims(hasher)).sort();
  }

  public async presentableKeys(hasher: Hasher): Promise<string[]> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SDJWTException('Invalid sd-jwt: jwt or disclosures is missing');
    }
    const { disclosureKeymap } = await unpack(
      this.jwt?.payload,
      this.disclosures,
      hasher,
    );
    return Object.keys(disclosureKeymap).sort();
  }

  public async getClaims<T>(hasher: Hasher): Promise<T> {
    if (!this.jwt?.payload || !this.disclosures) {
      throw new SDJWTException('Invalid sd-jwt: jwt or disclosures is missing');
    }
    const { unpackedObj } = await unpack(
      this.jwt.payload,
      this.disclosures,
      hasher,
    );
    return unpackedObj as T;
  }
}

export const listKeys = (obj: any, prefix: string = '') => {
  const keys: string[] = [];
  for (let key in obj) {
    if (obj[key] === undefined) continue;
    const newKey = prefix ? `${prefix}.${key}` : key;
    keys.push(newKey);

    if (obj[key] && typeof obj[key] === 'object' && obj[key] !== null) {
      keys.push(...listKeys(obj[key], newKey));
    }
  }
  return keys;
};

export const pack = async <T extends object>(
  claims: T,
  disclosureFrame: DisclosureFrame<T> | undefined,
  hash: HasherAndAlg,
  saltGenerator: SaltGenerator,
): Promise<{ packedClaims: any; disclosures: Array<Disclosure<any>> }> => {
  if (!disclosureFrame) {
    return {
      packedClaims: claims,
      disclosures: [],
    };
  }

  const sd = disclosureFrame[SD_DIGEST] ?? [];
  const decoyCount = disclosureFrame[SD_DECOY] ?? 0;

  if (claims instanceof Array) {
    const packedClaims: any[] = [];
    const disclosures: any[] = [];
    const recursivePackedClaims: any = {};

    for (const key in disclosureFrame) {
      if (key !== SD_DIGEST) {
        const idx = parseInt(key);
        const packed = await pack(
          claims[idx],
          // @ts-ignore
          disclosureFrame[idx],
          hash,
          saltGenerator,
        );
        recursivePackedClaims[idx] = packed.packedClaims;
        disclosures.push(...packed.disclosures);
      }
    }

    for (let i = 0; i < (claims as Array<any>).length; i++) {
      const claim = recursivePackedClaims[i]
        ? recursivePackedClaims[i]
        : claims[i];
      // @ts-ignore
      if (sd.includes(i)) {
        const salt = await saltGenerator(16);
        const disclosure = new Disclosure([salt, claim]);
        const digest = await disclosure.digest(hash);
        packedClaims.push({ [SD_LIST_KEY]: digest });
        disclosures.push(disclosure);
      } else {
        packedClaims.push(claim);
      }
    }
    for (let j = 0; j < decoyCount; j++) {
      const decoyDigest = await createDecoy(hash, saltGenerator);
      packedClaims.push({ [SD_LIST_KEY]: decoyDigest });
    }
    return { packedClaims, disclosures };
  }

  const packedClaims: any = {};
  const disclosures: any[] = [];
  const recursivePackedClaims: any = {};
  for (const key in disclosureFrame) {
    if (key !== SD_DIGEST) {
      const packed = await pack(
        // @ts-ignore
        claims[key],
        disclosureFrame[key],
        hash,
        saltGenerator,
      );
      recursivePackedClaims[key] = packed.packedClaims;
      disclosures.push(...packed.disclosures);
    }
  }

  const _sd: string[] = [];

  for (const key in claims) {
    const claim = recursivePackedClaims[key]
      ? recursivePackedClaims[key]
      : claims[key];
    // @ts-ignore
    if (sd.includes(key)) {
      const salt = await saltGenerator(16);
      const disclosure = new Disclosure([salt, key, claim]);
      const digest = await disclosure.digest(hash);

      _sd.push(digest);
      disclosures.push(disclosure);
    } else {
      packedClaims[key] = claim;
    }
  }

  for (let j = 0; j < decoyCount; j++) {
    const decoyDigest = await createDecoy(hash, saltGenerator);
    _sd.push(decoyDigest);
  }

  if (_sd.length > 0) {
    packedClaims[SD_DIGEST] = _sd.sort();
  }
  return { packedClaims, disclosures };
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
