export interface SDJWTVCStatusReference {
  // REQUIRED. implenentation according to https://www.ietf.org/archive/id/draft-ietf-oauth-status-list-02.html
  status_list: {
    // REQUIRED. index in the list of statuses
    idx: number;
    // REQUIRED. the reference to fetch the status list
    uri: string;
  };
}
