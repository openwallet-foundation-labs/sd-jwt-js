import { describe, expect, test } from 'vitest';
import {
  SD_SEPARATOR,
  SD_LIST_KEY,
  SD_DIGEST,
  SD_JWT_TYP,
  SD_DECOY,
  KB_JWT_TYP,
} from '../type';

describe('Variable tests', () => {
  test('SD_SEPARATOR', () => {
    expect(SD_SEPARATOR).toBe('~');
  });

  test('SD_LIST_KEY', () => {
    expect(SD_LIST_KEY).toBe('...');
  });

  test('SD_DIGEST', () => {
    expect(SD_DIGEST).toBe('_sd');
  });

  test('SD_JWT_TYP', () => {
    expect(SD_JWT_TYP).toBe('sd-jwt');
  });

  test('SD_DECOY', () => {
    expect(SD_DECOY).toBe('_sd_decoy');
  });

  test('KB_JWT_TYP', () => {
    expect(KB_JWT_TYP).toBe('kb+jwt');
  });
});
