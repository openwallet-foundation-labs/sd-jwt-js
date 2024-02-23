import { defineProject, mergeConfig } from 'vitest/config';
export const browserConfig = defineProject({
  test: {
    globals: true,
    environment: 'jsdom',
  },
});

export const nodeConfig = defineProject({
  test: {
    globals: true,
    environment: 'node',
  },
});

export const allEnvs = mergeConfig(browserConfig, nodeConfig);
