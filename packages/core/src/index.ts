import { SDJWTException } from '@sd-jwt/utils';
import { Jwt } from './jwt';
import { KBJwt } from './kbjwt';
import { SDJwt, pack } from './sdjwt';
import {
  DisclosureFrame,
  KBOptions,
  KB_JWT_TYP,
  SDJWTCompact,
  SDJWTConfig,
  SD_JWT_TYP,
} from '@sd-jwt/types';

export * from './sdjwt';
export * from './kbjwt';
export * from './jwt';
export * from './decoy';

export interface SdJwtVcPayload {
  // The Issuer of the Verifiable Credential. The value of iss MUST be a URI. See [RFC7519] for more information.
  iss: string;
  // The time of issuance of the Verifiable Credential. See [RFC7519] for more information.
  iat: number;
  // OPTIONAL. The time before which the Verifiable Credential MUST NOT be accepted before validating. See [RFC7519] for more information.
  nbf?: number;
  //OPTIONAL. The expiry time of the Verifiable Credential after which the Verifiable Credential is no longer valid. See [RFC7519] for more information.
  exp?: number;
  // REQUIRED when Cryptographic Key Binding is to be supported. Contains the confirmation method as defined in [RFC7800]. It is RECOMMENDED that this contains a JWK as defined in Section 3.2 of [RFC7800]. For Cryptographic Key Binding, the Key Binding JWT in the Combined Format for Presentation MUST be signed by the key identified in this claim.
  cnf?: unknown;
  //REQUIRED. The type of the Verifiable Credential, e.g., https://credentials.example.com/identity_credential, as defined in Section 3.2.2.1.1.
  vct: string;
  // OPTIONAL. The information on how to read the status of the Verifiable Credential. See [I-D.looker-oauth-jwt-cwt-status-list] for more information.
  status?: unknown;

  //The identifier of the Subject of the Verifiable Credential. The Issuer MAY use it to provide the Subject identifier known by the Issuer. There is no requirement for a binding to exist between sub and cnf claims.
  sub?: string;

  // more entries
  [key: string]: unknown;
}

export class SDJwtInstance {
  public static DEFAULT_hashAlg = 'sha-256';

  private userConfig: SDJWTConfig = {};

  constructor(userConfig?: SDJWTConfig) {
    if (userConfig) {
      this.userConfig = userConfig;
    }
  }

  private async createKBJwt(options: KBOptions): Promise<KBJwt> {
    if (!this.userConfig.kbSigner) {
      throw new SDJWTException('Key Binding Signer not found');
    }
    if (!this.userConfig.kbSignAlg) {
      throw new SDJWTException('Key Binding sign algorithm not specified');
    }
    const { payload } = options;
    const kbJwt = new KBJwt({
      header: {
        typ: KB_JWT_TYP,
        alg: this.userConfig.kbSignAlg,
      },
      payload,
    });

    await kbJwt.sign(this.userConfig.kbSigner);
    return kbJwt;
  }

  private async SignJwt(jwt: Jwt) {
    if (!this.userConfig.signer) {
      throw new SDJWTException('Signer not found');
    }
    await jwt.sign(this.userConfig.signer);
    return jwt;
  }

  private async VerifyJwt(jwt: Jwt) {
    if (!this.userConfig.verifier) {
      throw new SDJWTException('Verifier not found');
    }
    return jwt.verify(this.userConfig.verifier);
  }

  public async issue<Payload extends SdJwtVcPayload>(
    payload: Payload,
    disclosureFrame?: DisclosureFrame<Payload>,
    options?: {
      header?: object; // This is for customizing the header of the jwt
    },
  ): Promise<SDJWTCompact> {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }

    if (!this.userConfig.saltGenerator) {
      throw new SDJWTException('SaltGenerator not found');
    }

    if (!this.userConfig.signAlg) {
      throw new SDJWTException('sign alogrithm not specified');
    }

    //validate disclosureFrame according to https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-01.html#section-3.2.2.2
    if (disclosureFrame?._sd) {
      const reservedNames = [
        'iss',
        'iat',
        'nbf',
        'exp',
        'cnf',
        'vct',
        'status',
      ];
      // check if there is any reserved names in the disclosureFrame._sd array
      const reservedNamesInDisclosureFrame = Object.keys(
        disclosureFrame._sd,
      ).filter((key) => reservedNames.includes(key));
      if (reservedNamesInDisclosureFrame.length > 0) {
        throw new SDJWTException(
          `Invalid disclosureFrame: reserved names in _sd array: ${reservedNamesInDisclosureFrame.join(
            ', ',
          )}`,
        );
      }
    }

    const hasher = this.userConfig.hasher;
    const hashAlg = this.userConfig.hashAlg ?? SDJwtInstance.DEFAULT_hashAlg;

    const { packedClaims, disclosures } = await pack(
      payload,
      disclosureFrame,
      { hasher, alg: hashAlg },
      this.userConfig.saltGenerator,
    );
    const alg = this.userConfig.signAlg;
    const OptionHeader = options?.header ?? {};
    const CustomHeader = this.userConfig.omitTyp
      ? OptionHeader
      : { typ: SD_JWT_TYP, ...OptionHeader };
    const header = { ...CustomHeader, alg };
    const jwt = new Jwt({
      header,
      payload: {
        ...packedClaims,
        _sd_alg: hashAlg,
      },
    });
    await this.SignJwt(jwt);

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
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const hasher = this.userConfig.hasher;

    const sdjwt = await SDJwt.fromEncode(encodedSDJwt, hasher);
    const kbJwt = options?.kb ? await this.createKBJwt(options.kb) : undefined;
    sdjwt.kbJwt = kbJwt;

    return sdjwt.present(presentationKeys.sort(), hasher);
  }

  // This function is for verifying the SD JWT
  // If requiredClaimKeys is provided, it will check if the required claim keys are presentation in the SD JWT
  // If requireKeyBindings is true, it will check if the key binding JWT is presentation and verify it
  public async verify(
    encodedSDJwt: string,
    requiredClaimKeys?: string[],
    requireKeyBindings?: boolean,
  ) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const hasher = this.userConfig.hasher;

    const sdjwt = await SDJwt.fromEncode(encodedSDJwt, hasher);
    if (!sdjwt.jwt) {
      throw new SDJWTException('Invalid SD JWT');
    }
    const { payload, header } = await this.validate(encodedSDJwt);

    if (requiredClaimKeys) {
      const keys = await sdjwt.keys(hasher);
      const missingKeys = requiredClaimKeys.filter((k) => !keys.includes(k));
      if (missingKeys.length > 0) {
        throw new SDJWTException(
          `Missing required claim keys: ${missingKeys.join(', ')}`,
        );
      }
    }

    if (!requireKeyBindings) {
      return { payload, header };
    }

    if (!sdjwt.kbJwt) {
      throw new SDJWTException('Key Binding JWT not exist');
    }
    if (!this.userConfig.kbVerifier) {
      throw new SDJWTException('Key Binding Verifier not found');
    }
    const kb = await sdjwt.kbJwt.verify(this.userConfig.kbVerifier);
    return { payload, header, kb };
  }

  // This function is for validating the SD JWT
  // Just checking signature and return its the claims
  public async validate(encodedSDJwt: string) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const hasher = this.userConfig.hasher;

    const sdjwt = await SDJwt.fromEncode(encodedSDJwt, hasher);
    if (!sdjwt.jwt) {
      throw new SDJWTException('Invalid SD JWT');
    }

    const verifiedPayloads = await this.VerifyJwt(sdjwt.jwt);
    const claims = await sdjwt.getClaims(hasher);
    return { payload: claims, header: verifiedPayloads.header };
  }

  public config(newConfig: SDJWTConfig) {
    this.userConfig = { ...this.userConfig, ...newConfig };
  }

  public encode(sdJwt: SDJwt): SDJWTCompact {
    return sdJwt.encodeSDJwt();
  }

  public decode(endcodedSDJwt: SDJWTCompact) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    return SDJwt.fromEncode(endcodedSDJwt, this.userConfig.hasher);
  }

  public async keys(endcodedSDJwt: SDJWTCompact) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const sdjwt = await SDJwt.fromEncode(endcodedSDJwt, this.userConfig.hasher);
    return sdjwt.keys(this.userConfig.hasher);
  }

  public async presentableKeys(endcodedSDJwt: SDJWTCompact) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const sdjwt = await SDJwt.fromEncode(endcodedSDJwt, this.userConfig.hasher);
    return sdjwt.presentableKeys(this.userConfig.hasher);
  }

  public async getClaims(endcodedSDJwt: SDJWTCompact) {
    if (!this.userConfig.hasher) {
      throw new SDJWTException('Hasher not found');
    }
    const sdjwt = await SDJwt.fromEncode(endcodedSDJwt, this.userConfig.hasher);
    return sdjwt.getClaims(this.userConfig.hasher);
  }
}
