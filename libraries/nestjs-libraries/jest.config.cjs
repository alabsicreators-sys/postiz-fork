/**
 * Standalone Jest config for the Nashir thin-fork unit tests.
 *
 * The repo's root jest.config.ts is vestigial: it imports '@nx/jest', which is
 * not a dependency of this workspace (and there is no nx.json), so `jest` from
 * the root config cannot run. Run these specs with:
 *
 *   npx jest -c libraries/nestjs-libraries/jest.config.cjs --coverage=false
 */
module.exports = {
  testEnvironment: 'node',
  roots: ['<rootDir>/src'],
  testMatch: ['**/*.spec.ts'],
  transform: {
    '^.+\.ts$': [
      'ts-jest',
      {
        tsconfig: {
          target: 'ES2021',
          module: 'commonjs',
          moduleResolution: 'node',
          esModuleInterop: true,
          experimentalDecorators: true,
          skipLibCheck: true,
          types: ['jest', 'node'],
        },
      },
    ],
  },
};
