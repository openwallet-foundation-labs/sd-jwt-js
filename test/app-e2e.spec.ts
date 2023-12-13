import Crypto from 'node:crypto';
import sdjwt, { SDJwt } from '../src';
import { DisclosureFrame } from '../src/type';

export const createKeyPair = () => {
  const { privateKey, publicKey } = Crypto.generateKeyPairSync('ed25519');
  return { privateKey, publicKey };
};

describe('App', () => {
  test('Example', async () => {
    const { privateKey, publicKey } = createKeyPair();
    const claims = {
      firstname: 'John',
      lastname: 'Doe',
      ssn: '123-45-6789',
      id: '1234',
      data: {
        firstname: 'John',
        lastname: 'Doe',
        ssn: '123-45-6789',
        list: [{ r: '1' }, 'b', 'c'],
      },
      data2: {
        hi: 'bye',
      },
    };
    const disclosureFrame: DisclosureFrame<typeof claims> = {
      _sd: ['firstname', 'id', 'data2'],
      data: {
        _sd: ['list'],
        _sd_decoy: 2,
        list: {
          _sd: [0, 2],
          _sd_decoy: 1,
          0: {
            _sd: ['r'],
          },
        },
      },
      data2: {
        _sd: ['hi'],
      },
    };
    const encodedSdjwt = await sdjwt.issue(claims, privateKey, disclosureFrame);
    expect(encodedSdjwt).toBeDefined();
    const validated = await sdjwt.validate(encodedSdjwt, publicKey);
    expect(validated).toEqual(true);

    const decoded = sdjwt.decode(encodedSdjwt);
    const keys = await decoded.keys();
    expect(keys).toEqual([
      'data',
      'data.firstname',
      'data.lastname',
      'data.list',
      'data.list.0',
      'data.list.0.r',
      'data.list.1',
      'data.list.2',
      'data.ssn',
      'data2',
      'data2.hi',
      'firstname',
      'id',
      'lastname',
      'ssn',
    ]);
    const payloads = await decoded.getClaims();
    expect(payloads).toEqual(claims);
    const presentableKeys = await decoded.presentableKeys();
    expect(presentableKeys).toEqual([
      'data2',
      'data2.hi',
      'firstname',
      'id',
      'list',
      'list.0',
      'list.0.r',
      'list.2',
    ]);

    const presentationFrame = ['firstname', 'id'];
    const presentedSDJwt = await sdjwt.present(encodedSdjwt, presentationFrame);
    expect(presentedSDJwt).toBeDefined();

    const presentationClaims = await sdjwt.getClaims(presentedSDJwt);
    expect(presentationClaims).toBeDefined();
    expect(presentationClaims).toEqual({
      lastname: 'Doe',
      ssn: '123-45-6789',
      data: { firstname: 'John', lastname: 'Doe', ssn: '123-45-6789' },
      id: '1234',
      firstname: 'John',
    });

    const requiredClaimKeys = ['firstname', 'id', 'data.ssn'];
    const verified = await sdjwt.verify(
      encodedSdjwt,
      publicKey,
      requiredClaimKeys,
    );
    expect(verified).toEqual(true);
  });
});
