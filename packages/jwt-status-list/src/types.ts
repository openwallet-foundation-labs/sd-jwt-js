import type { JwtPayload } from '@sd-jwt/types';

/**
 * Reference to a status list entry.
 */
export interface StatusListEntry {
  idx: number;
  uri: string;
}

/**
 * Payload for a JWT
 */
export interface JWTwithStatusListPayload extends JwtPayload {
  status: {
    status_list: StatusListEntry;
  };
}

/**
 * Payload for a JWT with a status list.
 */
export interface StatusListJWTPayload extends JwtPayload {
  ttl?: number;
  status_list: {
    bits: BitsPerStatus;
    lst: string;
  };
}

/**
 * BitsPerStatus type.
 */
export type BitsPerStatus = 1 | 2 | 4 | 8;

/**
 * Header parameters for a JWT.
 */
export type StatusListJWTHeaderParameters = {
  alg: string;
  typ: 'statuslist+jwt';
  [key: string]: unknown;
};
