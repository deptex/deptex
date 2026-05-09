/**
 * Unit tests for the snapshot runner's argv parser + diff-truncation helper.
 *
 * The full snapshot suite is Docker-gated (deptex-cli:local image required) and
 * therefore unrunnable in jest. These tests cover only the pure-function layer:
 * `parseSnapshotArgs` (argv → SnapshotRunnerArgs) and `truncateDiffLines`
 * (per-file diff cap with "…and N more" suffix).
 *
 * Importing test/snapshot.ts is safe because the file's main() entry is gated
 * on `require.main === module`.
 */

import {
  parseSnapshotArgs,
  truncateDiffLines,
  DEFAULT_MAX_DIFF,
} from '../../test/snapshot';

describe('parseSnapshotArgs', () => {
  it('returns sane defaults for empty argv', () => {
    const args = parseSnapshotArgs([]);
    expect(args).toEqual({
      fixture: undefined,
      only: undefined,
      update: false,
      diffOnly: false,
      includeSlow: false,
      maxDiff: DEFAULT_MAX_DIFF,
      help: false,
    });
  });

  it('exposes DEFAULT_MAX_DIFF as 200 (raised from 10)', () => {
    expect(DEFAULT_MAX_DIFF).toBe(200);
  });

  it('parses --update', () => {
    expect(parseSnapshotArgs(['--update']).update).toBe(true);
  });

  it('parses --diff-only', () => {
    expect(parseSnapshotArgs(['--diff-only']).diffOnly).toBe(true);
  });

  it('parses --include-slow', () => {
    expect(parseSnapshotArgs(['--include-slow']).includeSlow).toBe(true);
  });

  it('parses --fixture=<name>', () => {
    const args = parseSnapshotArgs(['--fixture=test-minimal-npm']);
    expect(args.fixture).toBe('test-minimal-npm');
  });

  it('parses --only=<n,n,n>', () => {
    const args = parseSnapshotArgs(['--only=test-empty,test-minimal-npm']);
    expect(args.only).toBe('test-empty,test-minimal-npm');
  });

  it('parses --help and short -h', () => {
    expect(parseSnapshotArgs(['--help']).help).toBe(true);
    expect(parseSnapshotArgs(['-h']).help).toBe(true);
  });

  it('parses --max-diff=<N> as a positive integer', () => {
    expect(parseSnapshotArgs(['--max-diff=500']).maxDiff).toBe(500);
    expect(parseSnapshotArgs(['--max-diff=10']).maxDiff).toBe(10);
  });

  it('parses --max-diff=0 as unlimited', () => {
    expect(parseSnapshotArgs(['--max-diff=0']).maxDiff).toBe(0);
  });

  it('throws on negative --max-diff', () => {
    expect(() => parseSnapshotArgs(['--max-diff=-1'])).toThrow(/non-negative integer/);
  });

  it('throws on non-integer --max-diff', () => {
    expect(() => parseSnapshotArgs(['--max-diff=abc'])).toThrow(/non-negative integer/);
    expect(() => parseSnapshotArgs(['--max-diff=1.5'])).toThrow(/non-negative integer/);
  });

  it('combines --diff-only with --update without throwing (caller resolves precedence)', () => {
    const args = parseSnapshotArgs(['--diff-only', '--update']);
    expect(args.diffOnly).toBe(true);
    expect(args.update).toBe(true);
  });

  it('parses a realistic combined invocation', () => {
    const args = parseSnapshotArgs([
      '--fixture=test-minimal-npm',
      '--diff-only',
      '--max-diff=50',
    ]);
    expect(args.fixture).toBe('test-minimal-npm');
    expect(args.diffOnly).toBe(true);
    expect(args.maxDiff).toBe(50);
    expect(args.update).toBe(false);
  });
});

describe('truncateDiffLines', () => {
  const lines = (n: number): string[] => Array.from({ length: n }, (_, i) => `diff-${i}`);

  it('returns a copy of the input when under cap', () => {
    const input = lines(5);
    const out = truncateDiffLines(input, 200);
    expect(out).toEqual(input);
    expect(out).not.toBe(input); // returned slice, not aliased
  });

  it('returns input unchanged when length === cap', () => {
    const input = lines(10);
    expect(truncateDiffLines(input, 10)).toEqual(input);
  });

  it('truncates at cap and appends "…and N more" suffix', () => {
    const input = lines(15);
    const out = truncateDiffLines(input, 10);
    expect(out).toHaveLength(11);
    expect(out.slice(0, 10)).toEqual(input.slice(0, 10));
    expect(out[10]).toBe('…and 5 more');
  });

  it('honours the new default of 200 (regression guard for old 10-cap)', () => {
    const input = lines(150);
    // At 200-cap, no truncation should happen for 150 lines.
    const out = truncateDiffLines(input, DEFAULT_MAX_DIFF);
    expect(out).toEqual(input);
    expect(out.find((l) => l.startsWith('…and'))).toBeUndefined();
  });

  it('treats maxDiff=0 as unlimited (no truncation, no suffix)', () => {
    const input = lines(1000);
    const out = truncateDiffLines(input, 0);
    expect(out).toEqual(input);
    expect(out.find((l) => l.startsWith('…and'))).toBeUndefined();
  });

  it('handles cap larger than input', () => {
    const input = lines(3);
    expect(truncateDiffLines(input, 1000)).toEqual(input);
  });

  it('handles empty input', () => {
    expect(truncateDiffLines([], 10)).toEqual([]);
    expect(truncateDiffLines([], 0)).toEqual([]);
  });
});
