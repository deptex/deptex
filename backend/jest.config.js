// Use <rootDir> so Jest resolves the mock path on all platforms (CI and local).
// rootDir is the directory containing this config (backend/).
const supabaseMockPath = '<rootDir>/src/test/mocks/lib-supabase-mock.js';

module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/extraction-worker/src'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  testPathIgnorePatterns: ['/node_modules/', 'src/test/aegis-analysis.test.ts', '/extraction-worker/node_modules/'],
  setupFilesAfterEnv: ['<rootDir>/jest.setup.js'],
  moduleNameMapper: {
    '^(\\.\\./)+lib/supabase$': supabaseMockPath,
    '^(\\.\\./)+backend/src/lib/supabase$': supabaseMockPath,
    '^.*backend/src/lib/supabase$': supabaseMockPath,
    '^supertest$': require.resolve('supertest'),
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      isolatedModules: true,
    }],
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
};
