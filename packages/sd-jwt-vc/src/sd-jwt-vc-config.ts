import type { SDJWTConfig } from '@sd-jwt/types';
import type { VcTFetcher } from './sd-jwt-vc-vct';

export type StatusListFetcher = (uri: string) => Promise<string>;
export type StatusValidator = (status: number) => Promise<void>;

/**
 * Configuration for SD-JWT-VC
 */
export type SDJWTVCConfig = SDJWTConfig & {
  // A function that fetches the status list from the uri. If not provided, the library will assume that the response is a compact JWT.
  statusListFetcher?: StatusListFetcher;
  // validte the status and decide if the status is valid or not. If not provided, the code will continue if it is 0, otherwise it will throw an error.
  statusValidator?: StatusValidator;
  // a function that fetches the type metadata format from the uri. If not provided, the library will assume that the response is a TypeMetadataFormat. Caching has to be implemented in this function. If the integrity value is passed, it to be validated according to https://www.w3.org/TR/SRI/
  vctFetcher?: VcTFetcher;
  // if set to true, it will load the metadata format based on the vct value. If not provided, it will default to false.
  loadTypeMetadataFormat?: boolean;
};
