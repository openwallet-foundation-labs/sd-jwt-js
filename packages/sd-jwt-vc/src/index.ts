import { SDJwtInstance } from '@sd-jwt/core';
import type { DisclosureFrame } from '@sd-jwt/types';
import { SDJWTException } from '../../utils/dist';
import type { SdJwtVcPayload } from './sd-jwt-vc-payload';
import { getListFromStatusListJWT } from '@sd-jwt/jwt-status-list';
import type { SDJWTVCConfig } from './sd-jwt-vc-config';
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
        return { payload: res.payload as SdJwtVcPayload, header: res.header };
      });

    if (result.payload.status) {
      //checks if a status field is present in the payload based on https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html
      if (result.payload.status.status_list) {
        // fetch the status list from the uri
        if (!this.userConfig.statusListFetcher) {
          throw new SDJWTException('Status list fetcher not found');
        }
        // fetch the status list from the uri
        const statusListJWT = await this.userConfig.statusListFetcher(
          result.payload.status.status_list.uri,
        );
        // get the status list from the status list JWT
        const statusList = getListFromStatusListJWT(statusListJWT);
        const status = statusList.getStatus(
          result.payload.status.status_list.idx,
        );
        // validate the status
        if (!this.userConfig.statusValidator) {
          throw new SDJWTException('Status validator not found');
        }
        await this.userConfig.statusValidator(status);
      }
    }

    return result;
  }
}
