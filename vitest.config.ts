import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    include: ['tests/**/*.test.ts'],
    environment: 'node',
    // Some cap tests build multi-megabyte strings (MAX_FILE_BYTES); give them room on slow machines.
    testTimeout: 30_000,
  },
});
