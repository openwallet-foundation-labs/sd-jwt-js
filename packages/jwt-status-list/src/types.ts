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
export interface JWTwithStatusListPayload extends JWTPayload {
  status: {
    status_list: StatusListEntry;
  };
}

/**
 * Payload for a JWT with a status list.
 */
export interface StatusListJWTPayload extends JWTPayload {
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
 * Payload for a JWT.
 */
export type JWTPayload = {
  iss: string;
  sub: string;
  iat: number;
  exp?: number;
  ttl?: number;
  [key: string]: unknown;
};

/**
 * Header parameters for a JWT.
 */
export type JWTHeaderParameters = {
  alg: string;
  [key: string]: unknown;
};
