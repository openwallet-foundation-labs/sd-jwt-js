// vite.config.ts
import { defineConfig } from 'vite';

export default defineConfig({
  test: {
    // Common test configuration
    globals: true,
    coverage: {
      reporter: ['text', 'json', 'html'],
    },
    environment: 'node', // Default environment
    // Override per environment as needed
  },
});
