'use strict';

// Mock jsonwebtoken so any route (e.g. notification-unsubscribe) that imports it
// can load in tests without needing a physical __mocks__ file (CI-safe).
jest.mock('jsonwebtoken', () => ({
  sign: jest.fn(() => 'mock-jwt-token'),
  verify: jest.fn((token, secret, opts, cb) => {
    if (typeof opts === 'function') {
      cb = opts;
      opts = undefined;
    }
    if (typeof cb === 'function') {
      cb(null, { sub: 'mock-user-id', email: 'test@example.com' });
      return;
    }
    return Promise.resolve({ sub: 'mock-user-id', email: 'test@example.com' });
  }),
  decode: jest.fn(() => ({ sub: 'mock-user-id' })),
}));
