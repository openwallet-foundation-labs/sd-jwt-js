import { generateSalt, digest, getHasher } from './crypto';
import { SDJWTException } from './error';
import { Jwt } from './jwt';
import { KBJwt } from './kbjwt';
import { SDJwt, pack } from './sdjwt';
import {
  DisclosureFrame,
  KBOptionWithSigner,
  KBOptions,
  KB_JWT_TYP,
  SDJWTCompact,
  SDJWTConfig,
  SD_JWT_TYP,
  SignOptions,
  Signer,
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
  signer: null,
  verifier: null,
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

  private isKBOptionsWithSigner(
    options: KBOptions,
  ): options is KBOptionWithSigner {
    if ((options as KBOptionWithSigner).signer) {
      return true;
    }
    return false;
  }

  private async createKBJwt(options: KBOptions): Promise<KBJwt> {
    const { alg, payload } = options;
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg,
      },
      payload,
    });

    if (this.isKBOptionsWithSigner(options)) {
      const { signer } = options;
      await kbJwt.signWithSigner(signer);
    } else {
      const { privateKey } = options;
      await kbJwt.sign(privateKey);
    }

    return kbJwt;
  }

  private async SignJwt(jwt: Jwt, signOption?: SignOptions) {
    if (!signOption) {
      const { signer } = this.userConfig;
      if (signer) {
        await jwt.signWithSigner(signer);
      }
      return jwt;
    }

    if ('signer' in signOption) {
      await jwt.signWithSigner(signOption.signer);
    } else {
      await jwt.sign(signOption.privateKey);
    }

    return jwt;
  }

  public async issue<Payload extends object>(
    payload: Payload,
    signOption?: SignOptions,
    disclosureFrame?: DisclosureFrame<Payload>,
    options?: {
      header?: object;
      sign_alg?: string;
      hash_alg?: string;
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
    const OptionHeader = options?.header ?? {};
    const CustomHeader = this.userConfig.omitTyp
      ? OptionHeader
      : { typ: SD_JWT_TYP, ...OptionHeader };
    const header = { ...CustomHeader, alg };
    const jwt = new Jwt({
      header,
      payload: {
        ...packedClaims,
        _sd_alg: options?.hash_alg ?? SDJwtInstance.DEFAULT_HASH_ALG,
      },
    });
    await this.SignJwt(jwt, signOption);

    const sdJwt = new SDJwt({
      jwt,
      disclosures,
    });

    return sdJwt.encodeSDJwt();
  }

  public async present(
    encodedSDJwt: string,
    presentationKeys?: string[],
    options?: {
      kb?: KBOptions;
    },
  ): Promise<SDJWTCompact> {
    if (!presentationKeys) return encodedSDJwt;
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);

    const kbJwt = options?.kb ? await this.createKBJwt(options.kb) : undefined;

    sdjwt.kbJwt = kbJwt;

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
  ) {
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);
    if (!sdjwt.jwt) {
      throw new SDJWTException('Invalid SD JWT');
    }
    const { payload, header } = await this.validate(encodedSDJwt, publicKey);

    if (requiredClaimKeys) {
      const keys = await sdjwt.keys();
      const missingKeys = requiredClaimKeys.filter((k) => !keys.includes(k));
      if (missingKeys.length > 0) {
        throw new SDJWTException(
          'Missing required claim keys: ' + missingKeys.join(', '),
        );
      }
    }

    if (options?.kb) {
      if (!sdjwt.kbJwt) {
        throw new SDJWTException('Key Binding JWT not exist');
      }
      const kb = await sdjwt.kbJwt.verify(options.kb.publicKey);
      return { payload, header, kb };
    }

    return { payload, header };
  }

  public async validate(encodedSDJwt: string, publicKey: Uint8Array | KeyLike) {
    const sdjwt = SDJwt.fromEncode(encodedSDJwt);
    if (!sdjwt.jwt) {
      throw new SDJWTException('Invalid SD JWT');
    }

    const verifiedPayloads = await sdjwt.jwt.verify(publicKey);
    const claims = await sdjwt.getClaims();
    return { payload: claims, header: verifiedPayloads.header };
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
