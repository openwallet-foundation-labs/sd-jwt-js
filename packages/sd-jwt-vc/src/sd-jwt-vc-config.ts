import type { SDJWTConfig } from '@sd-jwt/types';

/**
 * Configuration for SD-JWT-VC
 */
export type SDJWTVCConfig = SDJWTConfig & {
  // A function that fetches the status list from the uri. If not provided, the library will assume that the response is a compact JWT.
  statusListFetcher?: (uri: string) => Promise<string>;
  // validte the status and decide if the status is valid or not. If not provided, the code will continue if it is 0, otherwise it will throw an error.
  statusValidator?: (status: number) => Promise<void>;
};
