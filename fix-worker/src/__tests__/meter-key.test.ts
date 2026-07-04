// Billing-meter idempotency key: run 0 must keep the historical `:final`
// format (a standalone fix that recovery-retries ACROSS the worker deploy must
// not bill under two different key formats); only user wakes (run_seq > 0)
// move to the per-run `:run-N` key.

import { meterIdempotencyKey } from '../meter-event';

describe('meterIdempotencyKey', () => {
  test('run 0 keeps the historical :final key', () => {
    expect(meterIdempotencyKey('task-a', 0)).toBe('fix-worker:task-a:final');
  });

  test('undefined runSeq keeps the historical :final key', () => {
    expect(meterIdempotencyKey('task-a', undefined)).toBe('fix-worker:task-a:final');
  });

  test('a wake bills under its own per-run key', () => {
    expect(meterIdempotencyKey('task-a', 3)).toBe('fix-worker:task-a:run-3');
    expect(meterIdempotencyKey('task-a', 1)).toBe('fix-worker:task-a:run-1');
  });

  test('the same run always dedups to the same key', () => {
    expect(meterIdempotencyKey('task-a', 2)).toBe(meterIdempotencyKey('task-a', 2));
  });
});
