import { generateSalt, digest, getHasher } from './crypto';
import { Jwt } from './jwt';
import { KBJwt } from './kbjwt';
import { SDJwt, pack } from './sdjwt';
import {
  DisclosureFrame,
  KB_JWT_TYP,
  SDJWTCompact,
  SDJWTConfig,
  SD_JWT_TYP,
  kbPayload,
} from './type';
import { KeyLike } from 'jose';

export * from './type';
export * from './sdjwt';
export * from './kbjwt';
export * from './crypto';
export * from './jwt';
export * from './base64url';
export * from './decoy';
export * from './disclosure';

export const defaultConfig: Required<SDJWTConfig> = {
  omitTyp: false,
  hasher: digest,
  saltGenerator: generateSalt,
};

export class SDJwtInstance {
  public static DEFAULT_ALG = 'EdDSA';
  public static DEFAULT_HASH_ALG = 'sha-256';

  private userConfig: SDJWTConfig = {};

  constructor(userConfig?: SDJWTConfig) {
    if (userConfig) {
      this.userConfig = userConfig;
    }
  }

  public create(userConfig?: SDJWTConfig): SDJwtInstance {
    return new SDJwtInstance(userConfig);
  }

  private async createKBJwt(
    payload: kbPayload,
    privateKey: Uint8Array | KeyLike,
    alg: string,
  ): Promise<KBJwt> {
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg,
      },
      payload,
    });
    await kbJwt.sign(privateKey);
    return kbJwt;
  }

  public async issue<Payload extends object>(
    payload: Payload,
    privateKey: Uint8Array | KeyLike,
    disclosureFrame?: DisclosureFrame<Payload>,
    options?: {
      sign_alg?: string;
      hash_alg?: string;
      kb?: {
        alg: string;
        payload: kbPayload;
        privateKey: Uint8Array | KeyLike;
      };
    },
  ): Promise<SDJWTCompact> {
    const haser =
      this.userConfig.hasher ?? options?.hash_alg
        ? getHasher(options?.hash_alg)
        : defaultConfig.hasher;

    const { packedClaims, disclosures } = await pack(
      payload,
      disclosureFrame,
      haser,
      this.userConfig.saltGenerator ?? defaultConfig.saltGenerator,
    );
    const alg = options?.sign_alg ?? SDJwtInstance.DEFAULT_ALG;
    const header = this.userConfig.omitTyp ? { alg } : { alg, typ: SD_JWT_TYP };
    const jwt = new Jwt({
      header,
      payload: {
        ...packedClaims,
        _sd_alg: options?.hash_alg ?? SDJwtInstance.DEFAULT_HASH_ALG,
      },
    });
    await jwt.sign(privateKey);

    const kbJwt = options?.kb
      ? await this.createKBJwt(
          options.kb.payload,
          options.kb.privateKey,
          options.kb.alg,
        )
      : undefined;

    const sdJwt = new SDJwt({
      jwt,
      disclosures,
      kbJwt,
    });

    return sdJwt.encodeSDJwt();
  }

  public async present(
    encodedSDJwt: string,
    presentationKeys?: string[],
  ): Promise<SDJWTCompact> {
    if (!presentationKeys) return encodedSDJwt;
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);
    return sdjwt.present(presentationKeys.sort());
  }

  public async verify(
    encodedSDJwt: string,
    publicKey: Uint8Array | KeyLike,
    requiredClaimKeys?: string[],
    options?: {
      kb?: {
        publicKey: Uint8Array | KeyLike;
      };
    },
  ): Promise<boolean> {
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);
    if (!sdjwt.jwt) {
      return false;
    }
    const validated = await this.validate(encodedSDJwt, publicKey);
    if (!validated) {
      return false;
    }

    if (requiredClaimKeys) {
      const keys = await sdjwt.keys();
      const missingKeys = requiredClaimKeys.filter((k) => !keys.includes(k));
      if (missingKeys.length > 0) {
        return false;
      }
    }

    if (options?.kb) {
      if (!sdjwt.kbJwt) {
        return false;
      }
      const kbVerified = await sdjwt.kbJwt.verify(options.kb.publicKey);
      if (!kbVerified) {
        return false;
      }
    }

    return true;
  }

  public async validate(
    encodedSDJwt: string,
    publicKey: Uint8Array | KeyLike,
  ): Promise<boolean> {
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);
    if (!sdjwt.jwt) {
      return false;
    }

    const verified = await sdjwt.jwt.verify(publicKey);
    return verified;
  }

  public config(newConfig: SDJWTConfig) {
    this.userConfig = { ...this.userConfig, ...newConfig };
  }

  public encode(sdJwt: SDJwt): SDJWTCompact {
    return sdJwt.encodeSDJwt();
  }

  public decode(endcodedSDJwt: SDJWTCompact) {
    return SDJwt.fromEncode(endcodedSDJwt);
  }

  public keys(endcodedSDJwt: SDJWTCompact) {
    const sdjwt = SDJwt.fromEncode(endcodedSDJwt);
    return sdjwt.keys();
  }

  public presentableKeys(endcodedSDJwt: SDJWTCompact) {
    const sdjwt = SDJwt.fromEncode(endcodedSDJwt);
    return sdjwt.presentableKeys();
  }

  public getClaims(endcodedSDJwt: SDJWTCompact) {
    const sdjwt = SDJwt.fromEncode(endcodedSDJwt);
    return sdjwt.getClaims();
  }

  public getKeyBinding(endcodedSDJwt: SDJWTCompact) {
    const sdjwt = SDJwt.fromEncode(endcodedSDJwt);
    return sdjwt.kbJwt?.payload;
  }
}

const defaultInstance = new SDJwtInstance();
export default defaultInstance;
