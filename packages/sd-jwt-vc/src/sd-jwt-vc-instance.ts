import { Jwt, SDJwtInstance } from '@sd-jwt/core';
import type { DisclosureFrame, Verifier } from '@sd-jwt/types';
import { SDJWTException } from '@sd-jwt/utils';
import type { SdJwtVcPayload } from './sd-jwt-vc-payload';
import type { SDJWTVCConfig } from './sd-jwt-vc-config';
import {
  type StatusListJWTPayload,
  getListFromStatusListJWT,
} from '@sd-jwt/jwt-status-list';
import type { StatusListJWTHeaderParameters } from '@sd-jwt/jwt-status-list';
export class SDJwtVcInstance extends SDJwtInstance<SdJwtVcPayload> {
  /**
   * The type of the SD-JWT-VC set in the header.typ field.
   */
  protected type = 'vc+sd-jwt';

  protected userConfig: SDJWTVCConfig = {};

  constructor(userConfig?: SDJWTVCConfig) {
    super(userConfig);
    if (userConfig) {
      this.userConfig = userConfig;
    }
  }

  /**
   * Validates if the disclosureFrame contains any reserved fields. If so it will throw an error.
   * @param disclosureFrame
   */
  protected validateReservedFields(
    disclosureFrame: DisclosureFrame<SdJwtVcPayload>,
  ): void {
    //validate disclosureFrame according to https://www.ietf.org/archive/id/draft-ietf-oauth-sd-jwt-vc-03.html#section-3.2.2.2
    if (
      disclosureFrame?._sd &&
      Array.isArray(disclosureFrame._sd) &&
      disclosureFrame._sd.length > 0
    ) {
      const reservedNames = ['iss', 'nbf', 'exp', 'cnf', 'vct', 'status'];
      // check if there is any reserved names in the disclosureFrame._sd array
      const reservedNamesInDisclosureFrame = (
        disclosureFrame._sd as string[]
      ).filter((key) => reservedNames.includes(key));
      if (reservedNamesInDisclosureFrame.length > 0) {
        throw new SDJWTException('Cannot disclose protected field');
      }
    }
  }

  /**
   * Fetches the status list from the uri with a timeout of 10 seconds.
   * @param uri The URI to fetch from.
   * @returns A promise that resolves to a compact JWT.
   */
  private async statusListFetcher(uri: string): Promise<string> {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 10000);

    try {
      const response = await fetch(uri, {
        signal: controller.signal,
        headers: { Accept: 'application/statuslist+jwt' },
      });
      if (!response.ok) {
        throw new Error(
          `Error fetching status list: ${
            response.status
          } ${await response.text()}`,
        );
      }

      // according to the spec the content type should be application/statuslist+jwt
      if (
        response.headers.get('content-type') !== 'application/statuslist+jwt'
      ) {
        throw new Error('Invalid content type');
      }

      return response.text();
    } finally {
      clearTimeout(timeoutId);
    }
  }

  /**
   * Validates the status, throws an error if the status is not 0.
   * @param status
   * @returns
   */
  private async statusValidator(status: number): Promise<void> {
    if (status !== 0) throw new SDJWTException('Status is not valid');
    return Promise.resolve();
  }

  /**
   * Verifies the SD-JWT-VC.
   */
  async verify(
    encodedSDJwt: string,
    requiredClaimKeys?: string[],
    requireKeyBindings?: boolean,
  ) {
    // Call the parent class's verify method
    const result = await super
      .verify(encodedSDJwt, requiredClaimKeys, requireKeyBindings)
      .then((res) => {
        return {
          payload: res.payload as SdJwtVcPayload,
          header: res.header,
          kb: res.kb,
        };
      });

    if (result.payload.status) {
      //checks if a status field is present in the payload based on https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html
      if (result.payload.status.status_list) {
        // fetch the status list from the uri
        const fetcher =
          this.userConfig.statusListFetcher ?? this.statusListFetcher;
        // fetch the status list from the uri
        const statusListJWT = await fetcher(
          result.payload.status.status_list.uri,
        );

        const slJWT = Jwt.fromEncode<
          StatusListJWTHeaderParameters,
          StatusListJWTPayload
        >(statusListJWT);
        // check if the status list has a valid signature. The presence of the verifier is checked in the parent class.
        await slJWT.verify(this.userConfig.verifier as Verifier);

        //check if the status list is expired
        if (
          slJWT.payload?.exp &&
          (slJWT.payload.exp as number) < Date.now() / 1000
        ) {
          throw new SDJWTException('Status list is expired');
        }

        // get the status list from the status list JWT
        const statusList = getListFromStatusListJWT(statusListJWT);
        const status = statusList.getStatus(
          result.payload.status.status_list.idx,
        );

        // validate the status
        const statusValidator =
          this.userConfig.statusValidator ?? this.statusValidator;
        await statusValidator(status);
      }
    }

    return result;
  }
}
