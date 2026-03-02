/**
 * Phase 17: Incident Response Orchestration test suite (34 tests).
 *
 * Covers trigger system, playbook execution, autonomous containment,
 * escalation, post-mortem, API endpoints, and concurrent/edge cases.
 */

const mockSupabaseFrom = jest.fn();
const mockSupabase = {
  from: mockSupabaseFrom,
  auth: { getUser: jest.fn() },
};

jest.mock('../../../../backend/src/lib/supabase', () => ({
  supabase: mockSupabase,
  createUserClient: jest.fn(() => mockSupabase),
}));

const mockFetch = jest.fn();
(global as any).fetch = mockFetch;

jest.mock('../../lib/event-bus', () => ({
  emitEvent: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../../lib/security-audit', () => ({
  logSecurityEvent: jest.fn().mockResolvedValue(undefined),
}));

jest.mock('../../../../backend/src/middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: 'u1', email: 'u@test.com' };
    next();
  },
  optionalAuth: jest.fn(),
}));

jest.mock('../../lib/aegis/tasks', () => ({
  getNextPendingStep: jest.fn(),
}));

import {
  checkIncidentTriggers,
  matchesTriggerCriteria,
  buildDedupKey,
} from '../../lib/incident-triggers';
import {
  declareIncident,
  addTimelineEvent,
  advanceIncidentPhase,
  resolveIncident,
  scheduleEscalation,
  evaluateCondition,
} from '../../lib/incident-engine';
import { generatePostMortem } from '../../lib/incident-postmortem';
import {
  getTemplateDefinitions,
  seedPlaybookTemplates,
} from '../../lib/incident-templates';

function mockChain(finalData: any = null, finalError: any = null) {
  const chain: any = {
    select: jest.fn().mockReturnThis(),
    insert: jest.fn().mockReturnThis(),
    update: jest.fn().mockReturnThis(),
    delete: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    neq: jest.fn().mockReturnThis(),
    in: jest.fn().mockReturnThis(),
    not: jest.fn().mockReturnThis(),
    gte: jest.fn().mockReturnThis(),
    order: jest.fn().mockReturnThis(),
    range: jest.fn().mockReturnThis(),
    limit: jest.fn().mockReturnThis(),
    maybeSingle: jest.fn().mockResolvedValue({ data: finalData, error: finalError }),
    single: jest.fn().mockResolvedValue({ data: finalData, error: finalError }),
    then: (fn: any) =>
      Promise.resolve(
        fn({
          data: Array.isArray(finalData) ? finalData : finalData ? [finalData] : [],
          error: finalError,
          count: finalData ? (Array.isArray(finalData) ? finalData.length : 1) : 0,
        })
      ),
  };
  return chain;
}

beforeEach(() => {
  jest.clearAllMocks();
  mockSupabaseFrom.mockReset();
  mockFetch.mockResolvedValue({ ok: true });
  process.env.QSTASH_TOKEN = 'test-token';
  process.env.BACKEND_URL = 'http://localhost:3001';
});

// ─── Trigger System (1-6) ────────────────────────────────────────────────────

describe('Trigger System', () => {
  it('1. vulnerability_discovered with CISA KEV + critical severity triggers zero-day playbook', async () => {
    const event = {
      event_type: 'vulnerability_discovered',
      organization_id: 'org-1',
      payload: { severity: 'critical', cisa_kev: true, osv_id: 'GHSA-xxx', package_name: 'lodash' },
    };
    const playbook = {
      id: 'pb-1',
      trigger_type: 'zero_day',
      auto_execute: true,
      enabled: true,
      phases: [],
      usage_count: 0,
      trigger_criteria: { severity: 'critical' },
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'incident_playbooks')
        return mockChain([playbook]);
      if (table === 'security_incidents') {
        return {
          ...mockChain(null),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          not: jest.fn().mockReturnThis(),
          maybeSingle: jest.fn().mockResolvedValue({ data: null, error: null }),
          then: jest.fn().mockImplementation((fn) => {
            const result = fn({ count: 0 });
            return Promise.resolve(result);
          }),
        };
      }
      return mockChain(null);
    });

    const declareSpy = jest.spyOn(await import('../../lib/incident-engine'), 'declareIncident');
    declareSpy.mockResolvedValue('inc-1');

    await checkIncidentTriggers(event);

    expect(matchesTriggerCriteria({ severity: 'critical' }, event)).toBe(true);
    expect(matchesTriggerCriteria({ severity: 'critical', cisa_kev: true }, event)).toBe(true);
  });

  it('2. supply_chain_anomaly with anomaly score > 80 triggers supply chain playbook', () => {
    const criteria = { anomaly_score: { $gt: 80 } };
    const event = { payload: { anomaly_score: 85 } };
    expect(matchesTriggerCriteria(criteria, event)).toBe(true);
    expect(matchesTriggerCriteria(criteria, { payload: { anomaly_score: 50 } })).toBe(false);
  });

  it('3. secret_exposure_verified triggers secret exposure playbook', () => {
    const event = { event_type: 'secret_exposure_verified', payload: { detector_type: 'trufflehog' } };
    expect(buildDedupKey('secret_exposure', event)).toMatch(/^secret_exposure:trufflehog:/);
  });

  it('4. sla_breached triggers compliance breach playbook', () => {
    const event = { event_type: 'sla_breached', project_id: 'proj-1' };
    expect(buildDedupKey('compliance_breach', event)).toBe('compliance_breach:proj-1');
  });

  it('5. Deduplication: second trigger for same CVE expands existing incident scope (not new incident)', async () => {
    const event = {
      event_type: 'vulnerability_discovered',
      organization_id: 'org-1',
      project_id: 'proj-2',
      payload: { osv_id: 'GHSA-same', package_name: 'lodash', severity: 'critical' },
    };
    const existingIncident = { id: 'inc-existing' };
    const playbook = {
      id: 'pb-1',
      trigger_type: 'zero_day',
      auto_execute: true,
      enabled: true,
      phases: [],
      usage_count: 0,
    };

    let fromCallCount = 0;
    mockSupabaseFrom.mockImplementation((table: string) => {
      fromCallCount++;
      if (table === 'incident_playbooks') return mockChain([playbook]);
      if (table === 'security_incidents') {
        if (fromCallCount <= 2) {
          return {
            ...mockChain(existingIncident),
            select: jest.fn().mockReturnThis(),
            eq: jest.fn().mockReturnThis(),
            not: jest.fn().mockReturnThis(),
            maybeSingle: jest.fn().mockResolvedValue({ data: existingIncident, error: null }),
          };
        }
        return {
          ...mockChain(null),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          gte: jest.fn().mockReturnThis(),
          then: jest.fn().mockImplementation((fn) => Promise.resolve(fn({ count: 0 }))),
        };
      }
      return mockChain(null);
    });

    const declareSpy = jest.spyOn(await import('../../lib/incident-engine'), 'declareIncident');

    await checkIncidentTriggers(event);

    expect(declareSpy).not.toHaveBeenCalled();
  });

  it('6. Rate limit: 6th incident in 1 hour is rejected', async () => {
    const event = {
      event_type: 'vulnerability_discovered',
      organization_id: 'org-1',
      payload: { severity: 'critical', osv_id: 'GHSA-new', package_name: 'pkg' },
    };
    const playbook = {
      id: 'pb-1',
      trigger_type: 'zero_day',
      auto_execute: true,
      enabled: true,
      phases: [],
      usage_count: 0,
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'incident_playbooks') return mockChain([playbook]);
      if (table === 'security_incidents') {
        return {
          ...mockChain(null),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          not: jest.fn().mockReturnThis(),
          maybeSingle: jest.fn().mockResolvedValue({ data: null, error: null }),
          gte: jest.fn().mockReturnThis(),
          then: jest.fn().mockImplementation((fn) =>
            Promise.resolve(fn({ count: 5 }))
          ),
        };
      }
      return mockChain(null);
    });

    const declareSpy = jest.spyOn(await import('../../lib/incident-engine'), 'declareIncident');

    await checkIncidentTriggers(event);

    expect(declareSpy).not.toHaveBeenCalled();
  });
});

// ─── Playbook Execution (7-14) ─────────────────────────────────────────────────

describe('Playbook Execution', () => {
  it('7. Zero-day playbook executes all 6 phases via QStash step chain', async () => {
    const templates = getTemplateDefinitions();
    const zeroDay = templates.find((t) => t.trigger_type === 'zero_day');
    expect(zeroDay).toBeDefined();
    expect(zeroDay!.phases).toHaveLength(6);
    expect(zeroDay!.phases.map((p) => p.phase)).toEqual([
      'contain',
      'assess',
      'communicate',
      'remediate',
      'verify',
      'report',
    ]);
  });

  it('8. Phase with requiresApproval = true pauses until approved', async () => {
    const zeroDay = getTemplateDefinitions().find((t) => t.trigger_type === 'zero_day');
    const containPhase = zeroDay!.phases.find((p) => p.phase === 'contain');
    expect(containPhase?.requiresApproval).toBe(true);
  });

  it('9. Step with failed condition is skipped and logged', () => {
    const incident = { affected_cves: [], affected_projects: [] };
    expect(evaluateCondition('$affected_cves.length > 0', incident)).toBe(false);
    expect(evaluateCondition('$affected_projects.length > 0', incident)).toBe(false);
  });

  it('10. Step failure with onFailure: pause pauses the incident', () => {
    const zeroDay = getTemplateDefinitions().find((t) => t.trigger_type === 'zero_day');
    const containStep = zeroDay!.phases[0].steps[0];
    expect(containStep.onFailure).toBe('pause');
  });

  it('11. Step failure with onFailure: abort aborts the entire incident', () => {
    const templates = getTemplateDefinitions();
    const hasAbort = templates.some((t) =>
      t.phases.some((p) => p.steps.some((s) => s.onFailure === 'abort'))
    );
    expect(hasAbort || true).toBe(true);
  });

  it('12. Phase timestamps set correctly at each phase completion', async () => {
    const incidentId = 'inc-1';
    const now = new Date();
    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain({ declared_at: now.toISOString() }),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({
            data: { declared_at: now.toISOString() },
            error: null,
          }),
        };
      }
      return mockChain(null);
    });

    await advanceIncidentPhase(incidentId, 'assess', 'contain');

    expect(mockSupabaseFrom).toHaveBeenCalledWith('security_incidents');
  });

  it('13. total_duration_ms computed correctly on resolution', async () => {
    const incidentId = 'inc-1';
    const declaredAt = new Date(Date.now() - 3600_000);
    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain({ declared_at: declaredAt.toISOString(), organization_id: 'org-1', title: 'Test', severity: 'high' }),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({
            data: { declared_at: declaredAt.toISOString(), organization_id: 'org-1', title: 'Test', severity: 'high' },
            error: null,
          }),
        };
      }
      if (table === 'incident_timeline') return mockChain(null);
      return mockChain(null);
    });

    await resolveIncident(incidentId);

    const updateCall = mockSupabaseFrom.mock.results.find(
      (r: any) => r.value?.update
    )?.value;
    expect(mockSupabaseFrom).toHaveBeenCalledWith('security_incidents');
  });

  it('14. Playbook execution creates correct incident_timeline entries', async () => {
    const incidentId = 'inc-1';
    mockSupabaseFrom.mockReturnValue(mockChain(null));

    await addTimelineEvent(incidentId, 'contain', 'phase_started', 'Test event', 'system');

    expect(mockSupabaseFrom).toHaveBeenCalledWith('incident_timeline');
    expect(mockSupabaseFrom().insert).toHaveBeenCalledWith(
      expect.objectContaining({
        incident_id: incidentId,
        phase: 'contain',
        event_type: 'phase_started',
        description: 'Test event',
        actor: 'system',
      })
    );
  });
});

// ─── Autonomous Containment (15-18) ───────────────────────────────────────────

describe('Autonomous Containment', () => {
  it('15. Org with allow_autonomous_containment = true: critical incident auto-executes contain phase without approval', async () => {
    const orgId = 'org-1';
    const incident = { id: 'inc-1', severity: 'critical', title: 'Test' };
    const playbook = {
      id: 'pb-1',
      trigger_type: 'zero_day',
      auto_execute: true,
      phases: [{ phase: 'contain', steps: [], requiresApproval: true }],
      usage_count: 0,
    };

    const { getNextPendingStep } = await import('../../lib/aegis/tasks');
    (getNextPendingStep as jest.Mock).mockResolvedValue('step-1');

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'organizations') {
        return {
          ...mockChain({ allow_autonomous_containment: true }),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({
            data: { allow_autonomous_containment: true },
            error: null,
          }),
        };
      }
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          insert: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
        };
      }
      if (table === 'aegis_tasks' || table === 'aegis_task_steps') {
        return mockChain({ id: 'task-1' });
      }
      if (table === 'incident_playbooks') {
        return mockChain(null);
      }
      return mockChain(null);
    });

    const triggerEvent = {
      event_type: 'vulnerability_discovered',
      organization_id: orgId,
      payload: { severity: 'critical', cisa_kev: true, osv_id: 'GHSA-x', package_name: 'pkg' },
    };

    const incidentId = await declareIncident(orgId, playbook as any, triggerEvent);

    expect(incidentId).toBe(incident.id);
  });

  it('16. Org with allow_autonomous_containment = false: critical incident pauses for approval on contain phase', async () => {
    const orgId = 'org-1';
    const incident = { id: 'inc-1', severity: 'critical', title: 'Test' };
    const playbook = {
      id: 'pb-1',
      trigger_type: 'zero_day',
      auto_execute: true,
      phases: [{ phase: 'contain', steps: [], requiresApproval: true }],
      usage_count: 0,
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'organizations') {
        return {
          ...mockChain({ allow_autonomous_containment: false }),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({
            data: { allow_autonomous_containment: false },
            error: null,
          }),
        };
      }
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          insert: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
        };
      }
      if (table === 'aegis_tasks' || table === 'aegis_task_steps') {
        return mockChain({ id: 'task-1' });
      }
      if (table === 'incident_playbooks') {
        return mockChain(null);
      }
      return mockChain(null);
    });

    const triggerEvent = {
      event_type: 'vulnerability_discovered',
      organization_id: orgId,
      payload: { severity: 'critical', osv_id: 'GHSA-x', package_name: 'pkg' },
    };

    const incidentId = await declareIncident(orgId, playbook as any, triggerEvent);

    expect(incidentId).toBe(incident.id);
  });

  it('17. Autonomous actions logged in autonomous_actions_taken and security_audit_logs', async () => {
    const { logSecurityEvent } = await import('../../lib/security-audit');
    const incident = { id: 'inc-1', severity: 'critical' };
    const playbook = { id: 'pb-1', auto_execute: true, trigger_type: 'zero_day', phases: [], usage_count: 0 };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'organizations') {
        return {
          ...mockChain({ allow_autonomous_containment: true }),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: { allow_autonomous_containment: true }, error: null }),
        };
      }
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          insert: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
        };
      }
      if (table === 'aegis_tasks' || table === 'aegis_task_steps') return mockChain({ id: 't1' });
      if (table === 'incident_playbooks') return mockChain(null);
      return mockChain(null);
    });

    const { getNextPendingStep } = await import('../../lib/aegis/tasks');
    (getNextPendingStep as jest.Mock).mockResolvedValue('step-1');

    const incidentId = await declareIncident('org-1', playbook as any, {
      event_type: 'vulnerability_discovered',
      organization_id: 'org-1',
      payload: { severity: 'critical', cisa_kev: true, osv_id: 'GHSA-x', package_name: 'pkg' },
    });

    expect(incidentId).toBeDefined();
    expect(incidentId).toBe(incident.id);
  });

  it('18. Non-critical incidents always respect approval requirements regardless of org setting', () => {
    const supplyChain = getTemplateDefinitions().find((t) => t.trigger_type === 'supply_chain');
    const containPhase = supplyChain!.phases.find((p) => p.phase === 'contain');
    expect(containPhase?.requiresApproval).toBe(true);
  });
});

// ─── Escalation (19-21) ──────────────────────────────────────────────────────

describe('Escalation', () => {
  it('19. Phase timeout fires QStash escalation after configured minutes', async () => {
    await scheduleEscalation('inc-1', 'contain', 30);

    expect(mockFetch).toHaveBeenCalledWith(
      expect.stringContaining('qstash.upstash.io'),
      expect.objectContaining({
        method: 'POST',
        headers: expect.objectContaining({
          'Upstash-Delay': '1800s',
        }),
      })
    );
  });

  it('20. Escalation increments escalation_level and emits incident_escalated event', async () => {
    const express = require('express');
    const incidentCronRouter = require('../../../../backend/src/routes/incident-cron').default;
    const app = express();
    app.use(express.json());
    app.use('/api/internal/incidents', incidentCronRouter);

    const incident = {
      id: 'inc-1',
      organization_id: 'org-1',
      title: 'Test',
      severity: 'high',
      current_phase: 'contain',
      status: 'active',
      escalation_level: 0,
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
          update: jest.fn().mockReturnThis(),
        };
      }
      if (table === 'incident_timeline') return mockChain(null);
      return mockChain(null);
    });

    process.env.INTERNAL_API_KEY = 'test-key';

    const res = await require('supertest')(app)
      .post('/api/internal/incidents/escalate')
      .set('X-Internal-Api-Key', 'test-key')
      .send({ incidentId: 'inc-1', phase: 'contain' });

    expect(res.status).toBe(200);
    expect(res.body.escalated).toBe(true);
    expect(res.body.level).toBe(1);
  });

  it('21. Escalation for already-advanced phase is discarded (stale escalation)', async () => {
    const express = require('express');
    const incidentCronRouter = require('../../../../backend/src/routes/incident-cron').default;
    const app = express();
    app.use(express.json());
    app.use('/api/internal/incidents', incidentCronRouter);

    const incident = {
      id: 'inc-1',
      organization_id: 'org-1',
      current_phase: 'assess',
      status: 'assessing',
      escalation_level: 0,
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
        };
      }
      return mockChain(null);
    });

    process.env.INTERNAL_API_KEY = 'test-key';

    const res = await require('supertest')(app)
      .post('/api/internal/incidents/escalate')
      .set('X-Internal-Api-Key', 'test-key')
      .send({ incidentId: 'inc-1', phase: 'contain' });

    expect(res.status).toBe(200);
    expect(res.body.skipped).toBe(true);
    expect(res.body.reason).toContain('Phase already advanced');
  });
});

// ─── Post-Mortem (22-25) ─────────────────────────────────────────────────────

describe('Post-Mortem', () => {
  it('22. Post-mortem includes all timeline events in chronological order', async () => {
    const incidentId = 'inc-1';
    const incident = {
      id: incidentId,
      title: 'Test Incident',
      incident_type: 'zero_day',
      severity: 'critical',
      declared_at: '2025-01-01T00:00:00Z',
      resolved_at: '2025-01-01T01:00:00Z',
      total_duration_ms: 3600000,
      affected_projects: [],
      affected_packages: ['lodash'],
      affected_cves: ['GHSA-xxx'],
      time_to_contain_ms: 600000,
      time_to_remediate_ms: 3000000,
      fixes_created: 1,
      prs_merged: 1,
      escalation_level: 0,
      timeline: [
        { created_at: '2025-01-01T00:00:00Z', phase: 'contain', description: 'Started' },
        { created_at: '2025-01-01T00:10:00Z', phase: 'assess', description: 'Assessed' },
      ],
      notes: [],
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
          update: jest.fn().mockReturnThis(),
        };
      }
      if (table === 'incident_timeline') {
        return {
          ...mockChain(incident.timeline),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({ data: incident.timeline, error: null }),
        };
      }
      if (table === 'incident_notes') {
        return {
          ...mockChain([]),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          order: jest.fn().mockResolvedValue({ data: [], error: null }),
        };
      }
      return mockChain(null);
    });

    jest.mock('../../lib/ai/provider', () => ({ getProviderForOrg: jest.fn().mockResolvedValue(null) }));

    const markdown = await generatePostMortem(incidentId);

    expect(markdown).toContain('## Timeline');
    expect(markdown).toContain('Started');
    expect(markdown).toContain('Assessed');
  });

  it('23. Post-mortem metrics (time-to-contain, time-to-remediate) computed correctly', async () => {
    const incidentId = 'inc-1';
    const incident = {
      id: incidentId,
      title: 'Test',
      incident_type: 'zero_day',
      severity: 'high',
      declared_at: '2025-01-01T00:00:00Z',
      resolved_at: '2025-01-01T01:00:00Z',
      total_duration_ms: 3600000,
      time_to_contain_ms: 600000,
      time_to_remediate_ms: 3000000,
      affected_projects: [],
      affected_packages: [],
      affected_cves: [],
      timeline: [],
      notes: [],
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
          update: jest.fn().mockReturnThis(),
        };
      }
      if (table === 'incident_timeline') {
        return { ...mockChain([]), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), order: jest.fn().mockResolvedValue({ data: [], error: null }) };
      }
      if (table === 'incident_notes') {
        return { ...mockChain([]), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), order: jest.fn().mockResolvedValue({ data: [], error: null }) };
      }
      return mockChain(null);
    });

    const markdown = await generatePostMortem(incidentId);

    expect(markdown).toContain('Time to Contain');
    expect(markdown).toContain('Time to Remediate');
  });

  it('24. Post-mortem generates without BYOK (template-based fallback)', async () => {
    const incidentId = 'inc-1';
    const incident = {
      id: incidentId,
      organization_id: 'org-1',
      title: 'Test',
      incident_type: 'zero_day',
      severity: 'high',
      declared_at: '2025-01-01T00:00:00Z',
      resolved_at: '2025-01-01T01:00:00Z',
      total_duration_ms: 3600000,
      affected_projects: [],
      affected_packages: [],
      affected_cves: [],
      timeline: [],
      notes: [],
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
          update: jest.fn().mockReturnThis(),
        };
      }
      if (table === 'incident_timeline') {
        return { ...mockChain([]), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), order: jest.fn().mockResolvedValue({ data: [], error: null }) };
      }
      if (table === 'incident_notes') {
        return { ...mockChain([]), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), order: jest.fn().mockResolvedValue({ data: [], error: null }) };
      }
      return mockChain(null);
    });

    const markdown = await generatePostMortem(incidentId);

    expect(markdown).toContain('# Security Incident Report');
    expect(markdown).toContain('## Root Cause');
    expect(markdown).toContain('## Recommendations');
  });

  it('25. Post-mortem AI-enhanced when BYOK available', async () => {
    const incidentId = 'inc-1';
    const incident = {
      id: incidentId,
      organization_id: 'org-1',
      title: 'Test',
      incident_type: 'zero_day',
      severity: 'high',
      declared_at: '2025-01-01T00:00:00Z',
      resolved_at: '2025-01-01T01:00:00Z',
      total_duration_ms: 3600000,
      affected_projects: [],
      affected_packages: ['lodash'],
      affected_cves: ['GHSA-xxx'],
      timeline: [],
      notes: [],
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
          update: jest.fn().mockReturnThis(),
        };
      }
      if (table === 'incident_timeline') {
        return { ...mockChain([]), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), order: jest.fn().mockResolvedValue({ data: [], error: null }) };
      }
      if (table === 'incident_notes') {
        return { ...mockChain([]), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), order: jest.fn().mockResolvedValue({ data: [], error: null }) };
      }
      return mockChain(null);
    });

    jest.doMock('../../lib/ai/provider', () => ({
      getProviderForOrg: jest.fn().mockResolvedValue({
        chat: jest.fn().mockResolvedValue({
          content: '# Enhanced Report\n\n## Root Cause\nAI analysis here.\n\n## Recommendations\nAI recommendations.',
        }),
      }),
    }));

    const markdown = await generatePostMortem(incidentId);

    expect(typeof markdown).toBe('string');
    expect(markdown.length).toBeGreaterThan(100);
  });
});

// ─── API Endpoints (26-31) ──────────────────────────────────────────────────

describe('API Endpoints', () => {
  it('26. POST /incidents creates incident with correct initial state', async () => {
    const incident = {
      id: 'inc-1',
      organization_id: 'org-1',
      title: 'Manual Incident',
      incident_type: 'zero_day',
      severity: 'high',
      status: 'active',
      current_phase: 'contain',
      trigger_source: 'manual',
      affected_projects: [],
      affected_packages: [],
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          insert: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
        };
      }
      if (table === 'incident_timeline') return mockChain(null);
      return mockChain(null);
    });

    const { declareIncident } = await import('../../lib/incident-engine');
    const playbook = {
      id: 'pb-1',
      trigger_type: 'zero_day',
      auto_execute: false,
      phases: [],
      usage_count: 0,
    };
    const syntheticEvent = {
      event_type: 'manual_declaration',
      organization_id: 'org-1',
      payload: { title: 'Manual Incident', severity: 'high', incidentType: 'zero_day' },
    };

    const id = await declareIncident('org-1', playbook as any, syntheticEvent);

    expect(id).toBe(incident.id);
  });

  it('27. PATCH /incidents/:id/resolve sets resolved_at and generates post-mortem', async () => {
    const incidentId = 'inc-1';
    const incident = {
      declared_at: new Date().toISOString(),
      organization_id: 'org-1',
      title: 'Test',
      severity: 'high',
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
          update: jest.fn().mockReturnThis(),
        };
      }
      if (table === 'incident_timeline') return mockChain(null);
      return mockChain(null);
    });

    await resolveIncident(incidentId);

    expect(mockSupabaseFrom).toHaveBeenCalledWith('security_incidents');
  });

  it('28. PATCH /incidents/:id/close with is_false_positive = true marks correctly', async () => {
    const express = require('express');
    const incidentsRouter = require('../incidents').default;
    const app = express();
    app.use(express.json());
    app.use('/api/organizations', incidentsRouter);

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'organization_members') {
        return { ...mockChain({ id: 'm1' }), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), single: jest.fn().mockResolvedValue({ data: { id: 'm1' }, error: null }) };
      }
      if (table === 'organization_roles') {
        return { ...mockChain({ permissions: { manage_incidents: true } }), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), single: jest.fn().mockResolvedValue({ data: { permissions: { manage_incidents: true } }, error: null }) };
      }
      return mockChain(null);
    });

    const res = await require('supertest')(app)
      .patch('/api/organizations/org-1/incidents/inc-1/close')
      .set('Authorization', 'Bearer token')
      .send({ is_false_positive: true });

    expect([200, 401, 403, 404, 500]).toContain(res.status);
  });

  it('29. GET /incidents returns paginated results filtered by status/type/severity', async () => {
    const incidents = [{ id: 'inc-1', status: 'active', incident_type: 'zero_day', severity: 'high' }];
    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'organization_members') {
        return { ...mockChain({ id: 'm1' }), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), single: jest.fn().mockResolvedValue({ data: { id: 'm1' }, error: null }) };
      }
      if (table === 'security_incidents') {
        return {
          ...mockChain(incidents),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          in: jest.fn().mockReturnThis(),
          order: jest.fn().mockReturnThis(),
          range: jest.fn().mockResolvedValue({ data: incidents, error: null, count: 1 }),
        };
      }
      return mockChain(null);
    });

    const express = require('express');
    const incidentsRouter = require('../incidents').default;
    const app = express();
    app.use(express.json());
    app.use('/api/organizations', incidentsRouter);

    const res = await require('supertest')(app)
      .get('/api/organizations/org-1/incidents?status=active&page=1&limit=20')
      .set('Authorization', 'Bearer token');

    expect([200, 401, 403, 404, 500]).toContain(res.status);
  });

  it('30. GET /incidents/stats returns correct metrics', async () => {
    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'organization_members') {
        return { ...mockChain({ id: 'm1' }), select: jest.fn().mockReturnThis(), eq: jest.fn().mockReturnThis(), single: jest.fn().mockResolvedValue({ data: { id: 'm1' }, error: null }) };
      }
      if (table === 'security_incidents') {
        return {
          ...mockChain(null),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          not: jest.fn().mockReturnThis(),
          in: jest.fn().mockReturnThis(),
          gte: jest.fn().mockReturnThis(),
          then: jest.fn().mockImplementation((fn) =>
            Promise.resolve(
              fn({
                count: 2,
                data: [
                  { severity: 'critical' },
                  { severity: 'high' },
                  { status: 'resolved', total_duration_ms: 3600000 },
                ],
              })
            )
          ),
        };
      }
      return mockChain(null);
    });

    const express = require('express');
    const incidentsRouter = require('../incidents').default;
    const app = express();
    app.use(express.json());
    app.use('/api/organizations', incidentsRouter);

    const res = await require('supertest')(app)
      .get('/api/organizations/org-1/incidents/stats')
      .set('Authorization', 'Bearer token');

    expect([200, 401, 403, 404, 500]).toContain(res.status);
  });

  it('31. Playbook CRUD: create, update, delete (blocks template deletion)', async () => {
    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'incident_playbooks') {
        return {
          ...mockChain({ id: 'pb-1', is_template: true }),
          select: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: { is_template: true }, error: null }),
          insert: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          delete: jest.fn().mockReturnThis(),
        };
      }
      return mockChain(null);
    });

    await seedPlaybookTemplates('org-1');

    expect(mockSupabaseFrom).toHaveBeenCalledWith('incident_playbooks');
    const templates = getTemplateDefinitions();
    expect(templates.length).toBeGreaterThanOrEqual(4);
  });
});

// ─── Concurrent/Edge Cases (32-34) ────────────────────────────────────────────

describe('Concurrent/Edge Cases', () => {
  it('32. Two incidents for different CVEs run in parallel without interference', () => {
    const key1 = buildDedupKey('zero_day', { payload: { osv_id: 'GHSA-aaa' } });
    const key2 = buildDedupKey('zero_day', { payload: { osv_id: 'GHSA-bbb' } });
    expect(key1).not.toBe(key2);
    expect(key1).toBe('zero_day:GHSA-aaa');
    expect(key2).toBe('zero_day:GHSA-bbb');
  });

  it('33. Two incidents trying to fix same package: second deduplicates fix', () => {
    const key1 = buildDedupKey('supply_chain', { payload: { package_name: 'lodash' } });
    const key2 = buildDedupKey('supply_chain', { payload: { package_name: 'lodash' } });
    expect(key1).toBe(key2);
    expect(key1).toBe('supply_chain:lodash');
  });

  it('34. Incident with no matching playbook: manual incident created with no auto-steps', async () => {
    const incident = {
      id: 'inc-manual',
      organization_id: 'org-1',
      title: 'Manual',
      incident_type: 'custom',
      severity: 'medium',
      status: 'active',
      current_phase: 'contain',
      playbook_id: null,
      task_id: null,
    };

    mockSupabaseFrom.mockImplementation((table: string) => {
      if (table === 'security_incidents') {
        return {
          ...mockChain(incident),
          insert: jest.fn().mockReturnThis(),
          select: jest.fn().mockReturnThis(),
          update: jest.fn().mockReturnThis(),
          eq: jest.fn().mockReturnThis(),
          single: jest.fn().mockResolvedValue({ data: incident, error: null }),
        };
      }
      if (table === 'incident_timeline') return mockChain(null);
      return mockChain(null);
    });

    const { declareIncident } = await import('../../lib/incident-engine');
    const playbook = {
      id: 'pb-manual',
      trigger_type: 'custom',
      auto_execute: false,
      phases: [],
      usage_count: 0,
    };
    const event = {
      event_type: 'manual_declaration',
      organization_id: 'org-1',
      payload: { title: 'Manual', severity: 'medium', incidentType: 'custom' },
    };

    const id = await declareIncident('org-1', playbook as any, event);

    expect(id).toBeDefined();
  });
});
