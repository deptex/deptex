/**
 * Canonical sample event payloads — one per event type in `EVENT_SCHEMAS`.
 *
 * Used by:
 *   - `runFlowCode` Test button (frontend → `/api/flows/validate-code`)
 *   - Save-time validator (`PUT /api/flows/:id`) when the request didn't carry a custom context
 *   - Conformance test ensures every schema field path resolves to a non-undefined value
 *
 * **Authoring notes:** payload shapes were captured from the live `emitEvent()`
 * call sites. When a new event type lands, add an entry here and update the
 * schema mirror in `event-schemas.ts`. The conformance test is the safety net.
 */

import { EVENT_SCHEMAS, type EventFieldSpec } from './event-schemas';

const PROJECT = {
  name: 'my-app',
  tier: 'Production',
  framework: 'react',
};

const DEPENDENCY = {
  name: 'lodash',
  version: '4.17.20',
  isDirect: true,
};

const INCIDENT = {
  incidentId: 'inc_test_0001',
  severity: 'high' as const,
  title: 'Critical vulnerability in lodash',
  project: { ...PROJECT },
};

export const SAMPLE_CONTEXTS: Record<string, Record<string, unknown>> = {
  vulnerability_discovered: {
    project: { ...PROJECT },
    dependency: { ...DEPENDENCY },
    vulnerability: {
      osvId: 'GHSA-test-0001',
      severity: 'high',
      cvssScore: 7.5,
      epssScore: 0.02,
      cisaKev: false,
      isReachable: true,
      reachabilityLevel: 'function',
      depscore: 62,
    },
  },

  malicious_package_detected: {
    project: { ...PROJECT, tier: 'Crown Jewels' },
    dependency: {
      ...DEPENDENCY,
      name: 'evil-package',
      version: '1.0.0',
      maliciousIndicator: {
        source: 'guarddog',
        confidence: 0.95,
        reason: 'Postinstall script downloads remote payload',
      },
    },
  },

  new_version_available: {
    project: { ...PROJECT },
    dependency: { ...DEPENDENCY, latestVersion: '4.17.21' },
  },

  project_created: {
    projectName: 'my-app',
    teamIds: 'team_abc',
  },

  project_deleted: {
    // Schema declares no fields; runtime hydrates project name from event context.
  },

  dependency_added: {
    project: { ...PROJECT },
    dependency: { ...DEPENDENCY, name: 'new-package', version: '1.0.0', license: 'MIT', score: 75 },
  },

  dependency_updated: {
    project: { ...PROJECT },
    dependency: { ...DEPENDENCY, version: '4.17.21', previousVersion: '4.17.20' },
  },

  status_changed: {
    project: { ...PROJECT },
    previous: { status: 'Compliant' },
  },

  policy_violation: {
    project: { ...PROJECT },
    policy: { codeType: 'packagePolicy' },
    violation: { message: 'AGPL-3.0 not allowed for Production tier' },
  },

  policy_code_updated: {
    codeType: 'packagePolicy',
    updatedBy: 'user_abc',
  },

  security_analysis_failure: {
    project: { ...PROJECT },
    stage: 'sbom_generation',
    error: 'cdxgen exited with code 1: missing manifest',
  },

  incident_declared: { ...INCIDENT },
  incident_auto_started: { ...INCIDENT },
  incident_escalated: { ...INCIDENT, severity: 'critical' },
  incident_contained: { ...INCIDENT },
  incident_resolved: { ...INCIDENT },
  incident_aborted: { ...INCIDENT },

  member_invited: {
    email: 'new-member@example.com',
    role: 'member',
    teamIds: 'team_abc,team_xyz',
  },

  member_removed: {
    removedEmail: 'former-member@example.com',
    removedUserId: 'user_xyz',
    selfRemoval: false,
  },

  integration_connected: {
    provider: 'slack',
    displayName: 'Engineering Slack',
  },

  integration_disconnected: {
    provider: 'slack',
    displayName: 'Engineering Slack',
  },
};

/**
 * Resolve a dot-path against an object, returning `undefined` if any segment is missing.
 * Used by the conformance test to verify every schema field has a sample value.
 */
export function resolvePath(obj: unknown, path: string): unknown {
  if (obj == null) return undefined;
  let cur: unknown = obj;
  for (const seg of path.split('.')) {
    if (cur == null || typeof cur !== 'object') return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

/**
 * Verify a sample context satisfies a list of schema fields. Returns the list
 * of fields that are missing or have a type mismatch. Empty array = conformant.
 */
export function findSchemaViolations(
  sample: Record<string, unknown>,
  fields: EventFieldSpec[],
): string[] {
  const violations: string[] = [];
  for (const f of fields) {
    const v = resolvePath(sample, f.path);
    if (v === undefined) {
      violations.push(`${f.path}: missing`);
      continue;
    }
    if (f.type === 'string' && typeof v !== 'string') {
      violations.push(`${f.path}: expected string, got ${typeof v}`);
    } else if (f.type === 'number' && typeof v !== 'number') {
      violations.push(`${f.path}: expected number, got ${typeof v}`);
    } else if (f.type === 'boolean' && typeof v !== 'boolean') {
      violations.push(`${f.path}: expected boolean, got ${typeof v}`);
    } else if (f.type === 'enum') {
      if (typeof v !== 'string') {
        violations.push(`${f.path}: expected enum string, got ${typeof v}`);
      } else if (f.enumValues && !f.enumValues.includes(v)) {
        violations.push(`${f.path}: value '${v}' not in [${f.enumValues.join(', ')}]`);
      }
    }
  }
  return violations;
}

export function getSampleContext(eventType: string): Record<string, unknown> | null {
  return SAMPLE_CONTEXTS[eventType] ?? null;
}

export { EVENT_SCHEMAS };
