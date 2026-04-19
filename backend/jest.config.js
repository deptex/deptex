module.exports = {
  preset: 'ts-jest',
  testEnvironment: 'node',
  roots: ['<rootDir>/src', '<rootDir>/extraction-worker/src', '<rootDir>/../ee/backend'],
  testMatch: ['**/__tests__/**/*.ts', '**/?(*.)+(spec|test).ts'],
  testPathIgnorePatterns: ['/node_modules/', 'src/test/aegis-analysis.test.ts', '/extraction-worker/node_modules/'],
  moduleNameMapper: {
    '^jsonwebtoken$': '<rootDir>/src/__mocks__/jsonwebtoken.js',
  },
  transform: {
    '^.+\\.tsx?$': ['ts-jest', {
      isolatedModules: true,
    }],
  },
  moduleFileExtensions: ['ts', 'tsx', 'js', 'jsx', 'json', 'node'],
};
