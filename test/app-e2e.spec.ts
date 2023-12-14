import Crypto from 'node:crypto';
import sdjwt from '../src';
import { DisclosureFrame } from '../src/type';
import fs from 'fs';
import path from 'path';

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
      'data.list',
      'data.list.0',
      'data.list.0.r',
      'data.list.2',
      'data2',
      'data2.hi',
      'firstname',
      'id',
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

  test('From JSON (Example1)', async () => {
    await JSONtest('./example1.json');
  });

  test('From JSON (array_data_types)', async () => {
    await JSONtest('./array_data_types.json');
  });

  test('From JSON (array_full_sd)', async () => {
    await JSONtest('./array_full_sd.json');
  });

  test('From JSON (array_in_sd)', async () => {
    await JSONtest('./array_in_sd.json');
  });
});

async function JSONtest(filename: string) {
  const test = loadTestJsonFile(filename);
  const { privateKey, publicKey } = createKeyPair();

  const encodedSdjwt = await sdjwt.issue(
    test.claims,
    privateKey,
    test.disclosureFrame,
  );

  expect(encodedSdjwt).toBeDefined();

  const validated = await sdjwt.validate(encodedSdjwt, publicKey);

  expect(validated).toEqual(true);

  const presentedSDJwt = await sdjwt.present(
    encodedSdjwt,
    test.presentationKeys,
  );

  expect(presentedSDJwt).toBeDefined();

  const presentationClaims = await sdjwt.getClaims(presentedSDJwt);

  expect(presentationClaims).toEqual(test.presenatedClaims);

  const verified = await sdjwt.verify(
    encodedSdjwt,
    publicKey,
    test.requiredClaimKeys,
  );

  expect(verified).toEqual(true);
}

type TestJson = {
  claims: object;
  disclosureFrame: DisclosureFrame<object>;
  presentationKeys: string[];
  presenatedClaims: object;
  requiredClaimKeys: string[];
};

function loadTestJsonFile(filename: string) {
  const filepath = path.join(__dirname, filename);
  const fileContents = fs.readFileSync(filepath, 'utf8');
  return JSON.parse(fileContents) as TestJson;
}
