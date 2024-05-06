import type { SDJWTConfig } from '@sd-jwt/types';

/**
 * Configuration for SD-JWT-VC
 */
export type SDJWTVCConfig = SDJWTConfig & {
  // A function that fetches the status list from the uri. It should also verify the status list JWT before returning the jwt.
  statusListFetcher?: (uri: string) => Promise<string>;
  // validte the status and decide if the status is valid or not. If the status is not valid, it should throw an error.
  statusValidator?: (status: number) => Promise<void>;
};
