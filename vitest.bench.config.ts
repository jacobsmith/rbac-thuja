import { defineConfig } from 'vitest/config';

// `npm run bench`: timing harness only, kept out of the regular test run.
export default defineConfig({
    test: {
        include: ['src/testing/**/*.bench-test.ts'],
    },
});
