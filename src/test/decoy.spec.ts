import { createDecoy } from '../decoy';

describe('Decoy', () => {
  test('decoy', async () => {
    const decoyValue = await createDecoy();
    expect(decoyValue.length).toBe(86);
  });

  test('apply hasher and saltGenerator', async () => {
    const decoyValue = await createDecoy(
      async (data) => data,
      () => 'salt',
    );
    expect(decoyValue).toBe('c2FsdA');
  });
});
