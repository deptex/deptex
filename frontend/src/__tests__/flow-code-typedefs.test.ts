/**
 * Tests for the runtime-built `.d.ts` strings fed to Monaco's TS extra-lib.
 * These run on every editor mount so they have to stay sub-millisecond and
 * reject malformed schemas loudly rather than producing invalid TS.
 */

import { describe, test, expect } from 'vitest';
import {
  buildEventDts,
  buildContractSignature,
  buildFlowCodeDts,
} from '../components/flow/flow-code-typedefs';

describe('buildEventDts', () => {
  test('produces a TS interface with nested objects and enum unions', () => {
    const dts = buildEventDts('vulnerability_discovered');
    expect(dts).toContain('interface VulnerabilityDiscoveredContext');
    expect(dts).toContain('vulnerability?:');
    expect(dts).toContain("severity?: 'critical' | 'high' | 'medium' | 'low'");
    expect(dts).toContain('cvssScore?: number;');
    expect(dts).toContain('cisaKev?: boolean;');
    expect(dts).toContain('project?:');
  });

  test('handles empty schema (project_deleted)', () => {
    const dts = buildEventDts('project_deleted');
    expect(dts).toBe('interface ProjectDeletedContext {}');
  });

  test('handles unknown event types as empty interface', () => {
    const dts = buildEventDts('not_a_real_event');
    expect(dts).toBe('interface NotARealEventContext {}');
  });

  test('flat-path events produce flat interfaces', () => {
    // policy_code_updated has only top-level paths (codeType, updatedBy)
    const dts = buildEventDts('policy_code_updated');
    expect(dts).toContain('codeType?:');
    expect(dts).toContain('updatedBy?: string;');
  });
});

describe('buildContractSignature', () => {
  test('builds the condition signature line', () => {
    expect(buildContractSignature('condition', 'vulnerability_discovered')).toBe(
      'function evaluate(context: VulnerabilityDiscoveredContext): boolean',
    );
  });

  test('falls back to unknown for unregistered nodeType', () => {
    expect(buildContractSignature('transform', 'vulnerability_discovered')).toBe(
      'function evaluate(context: unknown): unknown',
    );
  });
});

describe('buildFlowCodeDts', () => {
  test('combines event interface, helper declarations, and context binding', () => {
    const dts = buildFlowCodeDts('condition', 'vulnerability_discovered');
    expect(dts).toContain('interface VulnerabilityDiscoveredContext');
    expect(dts).toContain('declare function isLicenseAllowed');
    expect(dts).toContain('declare function semverGt');
    expect(dts).toContain('declare function daysSince');
    expect(dts).toContain('declare function fetch');
    expect(dts).toContain('declare const context: VulnerabilityDiscoveredContext;');
  });
});
