/**
 * Unit tests for the taint-engine AI spec parser/validator.
 *
 * The validator is the part that has to be airtight — a malformed AI
 * response shouldn't end up cached as a "spec" the engine then tries to
 * load. We test:
 *   - clean JSON parses + validates
 *   - JSON wrapped in ```json fences is unwrapped
 *   - bogus vuln_class is rejected
 *   - bogus taint_kind is rejected
 *   - missing required fields are rejected
 *   - framework name + version are forced to caller-provided values
 *     (the model frequently echoes them differently)
 */

import { parseAndValidateSpec, ALL_VULN_CLASSES } from '../taint-engine/spec-inference';

describe('taint-engine spec inference parser', () => {
  const goodSpec = {
    framework: 'demo',
    version: '*',
    sources: [{ pattern: 'req.body.*', taint_kind: 'http_input', description: 'd' }],
    sinks: [
      { pattern: 'eval(*)', vuln_class: 'command_injection', argument_indices: [0], description: 'd' },
    ],
    sanitizers: [
      { pattern: 'validator.escape(*)', vuln_classes: ['xss'], description: 'd' },
    ],
  };

  it('parses a clean JSON response', () => {
    const spec = parseAndValidateSpec(JSON.stringify(goodSpec), 'demo', '*');
    expect(spec.framework).toBe('demo');
    expect(spec.sources).toHaveLength(1);
    expect(spec.sinks[0].vuln_class).toBe('command_injection');
  });

  it('strips ```json code fences before parsing', () => {
    const wrapped = '```json\n' + JSON.stringify(goodSpec) + '\n```';
    const spec = parseAndValidateSpec(wrapped, 'demo', '*');
    expect(spec.sinks[0].pattern).toBe('eval(*)');
  });

  it('forces framework name + version to caller-provided values', () => {
    const echoed = { ...goodSpec, framework: 'wrong', version: '0.0.0' };
    const spec = parseAndValidateSpec(JSON.stringify(echoed), 'demo', '1.x');
    expect(spec.framework).toBe('demo');
    expect(spec.version).toBe('1.x');
  });

  it('rejects bogus vuln_class', () => {
    const bad = {
      ...goodSpec,
      sinks: [{ pattern: 'p', vuln_class: 'NOT_REAL', argument_indices: [], description: 'd' }],
    };
    expect(() => parseAndValidateSpec(JSON.stringify(bad), 'demo', '*')).toThrow(/vuln_class/);
  });

  it('rejects bogus taint_kind', () => {
    const bad = {
      ...goodSpec,
      sources: [{ pattern: 'p', taint_kind: 'mystery', description: 'd' }],
    };
    expect(() => parseAndValidateSpec(JSON.stringify(bad), 'demo', '*')).toThrow(/taint_kind/);
  });

  it('rejects missing description', () => {
    const bad = {
      ...goodSpec,
      sources: [{ pattern: 'req.body.*', taint_kind: 'http_input' }],
    };
    expect(() => parseAndValidateSpec(JSON.stringify(bad), 'demo', '*')).toThrow(/description/);
  });

  it('rejects non-array argument_indices', () => {
    const bad = {
      ...goodSpec,
      sinks: [{ pattern: 'p', vuln_class: 'xss', argument_indices: 'whoops', description: 'd' }],
    };
    expect(() => parseAndValidateSpec(JSON.stringify(bad), 'demo', '*')).toThrow(/argument_indices/);
  });

  it('rejects negative argument_indices', () => {
    const bad = {
      ...goodSpec,
      sinks: [{ pattern: 'p', vuln_class: 'xss', argument_indices: [-1], description: 'd' }],
    };
    expect(() => parseAndValidateSpec(JSON.stringify(bad), 'demo', '*')).toThrow(/non-negative/);
  });

  it('rejects non-JSON content', () => {
    expect(() => parseAndValidateSpec('definitely not json', 'demo', '*')).toThrow(/non-JSON/);
  });

  it('accepts every defined vuln_class in sanitizers', () => {
    const sanWithAll = {
      ...goodSpec,
      sanitizers: [{ pattern: 'p', vuln_classes: [...ALL_VULN_CLASSES], description: 'd' }],
    };
    const spec = parseAndValidateSpec(JSON.stringify(sanWithAll), 'demo', '*');
    expect(spec.sanitizers[0].vuln_classes).toHaveLength(ALL_VULN_CLASSES.length);
  });
});
