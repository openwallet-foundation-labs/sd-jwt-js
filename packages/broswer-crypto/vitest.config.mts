// vite.config.ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    // Common test configuration
    globals: true,
    coverage: {
      reporter: ['text', 'json', 'html'],
    },
    environment: 'jsdom', // Default environment
    // Override per environment as needed
  },
});
