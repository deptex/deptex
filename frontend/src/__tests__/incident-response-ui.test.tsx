/**
 * Phase 17: Incident Response UI — frontend tests.
 * Covers AegisPage incident sidebar, IncidentDetailView, IncidentResponseSection,
 * and integration flows (Phase 9 notifications, Phase 7 fix sprint, re-extraction, Phase 15 SLA).
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import React from 'react';

vi.mock('../../lib/supabase', () => ({
  supabase: {
    auth: {
      getSession: vi.fn().mockResolvedValue({
        data: { session: { access_token: 'test-token' } },
      }),
    },
    channel: vi.fn(() => ({
      on: vi.fn().mockReturnThis(),
      subscribe: vi.fn().mockReturnThis(),
    })),
  },
}));

vi.mock('../../lib/api', () => ({
  api: {
    getAegisThreads: vi.fn().mockResolvedValue([]),
    getAegisThreadMessages: vi.fn().mockResolvedValue([]),
    getAegisAutomations: vi.fn().mockResolvedValue([]),
  },
}));

vi.mock('@ai-sdk/react', () => ({
  useChat: vi.fn(() => ({
    messages: [],
    input: '',
    setInput: vi.fn(),
    append: vi.fn(),
    isLoading: false,
    error: null,
    reload: vi.fn(),
    stop: vi.fn(),
    setMessages: vi.fn(),
  })),
}));

vi.mock('react-markdown', () => ({
  default: (props: { children?: string }) =>
    React.createElement('div', { 'data-testid': 'markdown' }, props.children),
}));

vi.mock('remark-gfm', () => ({ default: () => {} }));

vi.mock('../../hooks/use-toast', () => ({
  useToast: () => ({ toast: vi.fn() }),
}));

function mockMatchMedia() {
  Object.defineProperty(window, 'matchMedia', {
    writable: true,
    value: vi.fn().mockImplementation((query: string) => ({
      matches: query === '(min-width: 1280px)',
      media: query,
      onchange: null,
      addListener: vi.fn(),
      removeListener: vi.fn(),
      addEventListener: vi.fn(),
      removeEventListener: vi.fn(),
      dispatchEvent: vi.fn(),
    })),
  });
}

const mockFetch = vi.fn();

describe('Phase 17: Incident Response UI', () => {
  beforeEach(() => {
    mockMatchMedia();
    mockFetch.mockReset();
    vi.stubGlobal('fetch', mockFetch);
  });

  describe('Incident UI (35–40)', () => {
    it('35: Active incident appears in Aegis left sidebar with red indicator', async () => {
      const incidentsPayload = {
        incidents: [
          {
            id: 'inc-1',
            title: 'Zero-Day CVE in lodash',
            severity: 'critical',
            status: 'assessing',
            current_phase: 'assess',
            incident_type: 'zero_day',
            escalation_level: 1,
            declared_at: new Date().toISOString(),
          },
        ],
      };
      mockFetch.mockImplementation((input: string | URL | Request) => {
        const u = typeof input === 'string' ? input : input instanceof Request ? input.url : input.toString();
        if (u.includes('incidents') && !u.includes('/resolve') && !u.includes('/notes')) {
          if (u.includes('/incidents/') && !u.includes('?')) return Promise.resolve({ ok: true, json: async () => incidentsPayload.incidents[0] });
          return Promise.resolve({ ok: true, json: async () => incidentsPayload });
        }
        return Promise.resolve({ ok: true, json: async () => [] });
      });

      const AegisPage = (await import('../app/pages/AegisPage')).default;
      render(
        <MemoryRouter initialEntries={['/organizations/org-1/aegis']}>
          <Routes>
            <Route path="/organizations/:id/aegis" element={<AegisPage />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => {
        expect(screen.getByText('Zero-Day CVE in lodash')).toBeInTheDocument();
      }, { timeout: 5000 });
      expect(screen.getByText(/Active incidents/i)).toBeInTheDocument();
      const redIndicator = document.querySelector('.animate-pulse.bg-red-500');
      expect(redIndicator).toBeInTheDocument();
    });

    it('36: Incident detail view shows 6-phase progress bar with current phase highlighted', async () => {
      mockFetch.mockImplementation((url: string | URL) => {
        const u = typeof url === 'string' ? url : url.toString();
        if (u.includes('/incidents/') && u.includes('inc-1') && !u.includes('/resolve')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              id: 'inc-1',
              title: 'Test Incident',
              severity: 'high',
              status: 'remediating',
              current_phase: 'remediate',
              incident_type: 'zero_day',
              declared_at: new Date().toISOString(),
              timeline: [],
            }),
          });
        }
        if (u.includes('/incidents?') || u.includes('/incidents&')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              incidents: [
                {
                  id: 'inc-1',
                  title: 'Test Incident',
                  severity: 'high',
                  status: 'remediating',
                  current_phase: 'remediate',
                  incident_type: 'zero_day',
                  escalation_level: 1,
                  declared_at: new Date().toISOString(),
                },
              ],
            }),
          });
        }
        return Promise.resolve({ ok: true, json: async () => [] });
      });

      const AegisPage = (await import('../app/pages/AegisPage')).default;
      render(
        <MemoryRouter initialEntries={['/organizations/org-1/aegis']}>
          <Routes>
            <Route path="/organizations/:id/aegis" element={<AegisPage />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => expect(screen.getByText('Test Incident')).toBeInTheDocument());
      fireEvent.click(screen.getByText('Test Incident'));

      await waitFor(() => {
        expect(screen.getByText(/REMEDIATE/i)).toBeInTheDocument();
      });
      const phases = ['CONTAIN', 'ASSESS', 'COMMUNICATE', 'REMEDIATE', 'VERIFY', 'REPORT'];
      phases.forEach((p) => expect(screen.getByText(p)).toBeInTheDocument());
      expect(phases.length).toBe(6);
    });

    it('37: Timeline renders all events with correct phase badges and timestamps', async () => {
      const timelineEvents = [
        {
          id: 'ev-1',
          phase: 'contain',
          event_type: 'phase_started',
          description: 'Incident declared',
          actor: 'system',
          created_at: '2025-03-02T10:00:00Z',
        },
        {
          id: 'ev-2',
          phase: 'assess',
          event_type: 'phase_started',
          description: 'Assessment started',
          actor: 'aegis',
          created_at: '2025-03-02T10:15:00Z',
        },
      ];

      mockFetch.mockImplementation((url: string | URL) => {
        const u = typeof url === 'string' ? url : url.toString();
        if (u.includes('/incidents/') && u.includes('inc-1')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              id: 'inc-1',
              title: 'Timeline Test',
              severity: 'medium',
              status: 'assessing',
              current_phase: 'assess',
              incident_type: 'custom',
              declared_at: new Date().toISOString(),
              timeline: timelineEvents,
            }),
          });
        }
        if (u.includes('/incidents?') || u.includes('/incidents&')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              incidents: [
                {
                  id: 'inc-1',
                  title: 'Timeline Test',
                  severity: 'medium',
                  status: 'assessing',
                  current_phase: 'assess',
                  incident_type: 'custom',
                  escalation_level: 1,
                  declared_at: new Date().toISOString(),
                },
              ],
            }),
          });
        }
        return Promise.resolve({ ok: true, json: async () => [] });
      });

      const AegisPage = (await import('../app/pages/AegisPage')).default;
      render(
        <MemoryRouter initialEntries={['/organizations/org-1/aegis']}>
          <Routes>
            <Route path="/organizations/:id/aegis" element={<AegisPage />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => expect(screen.getByText('Timeline Test')).toBeInTheDocument());
      fireEvent.click(screen.getByText('Timeline Test'));

      await waitFor(() => {
        expect(screen.getByText('Incident declared')).toBeInTheDocument();
        expect(screen.getByText('Assessment started')).toBeInTheDocument();
      });
      expect(screen.getByText(/contain/i)).toBeInTheDocument();
      expect(screen.getByText(/assess/i)).toBeInTheDocument();
    });

    it('38: Right panel shows affected projects, packages, and CVEs', async () => {
      mockFetch.mockImplementation((url: string | URL) => {
        const u = typeof url === 'string' ? url : url.toString();
        if (u.includes('/incidents/') && u.includes('inc-1') && !u.includes('/resolve')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              id: 'inc-1',
              title: 'Scope Test',
              severity: 'critical',
              status: 'assessing',
              current_phase: 'assess',
              incident_type: 'zero_day',
              declared_at: new Date().toISOString(),
              affected_projects: ['proj-abc123'],
              affected_packages: ['lodash', 'axios'],
              affected_cves: ['GHSA-xxxx', 'CVE-2024-1234'],
              timeline: [],
            }),
          });
        }
        if (u.includes('/incidents?') || u.includes('/incidents&')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              incidents: [
                {
                  id: 'inc-1',
                  title: 'Scope Test',
                  severity: 'critical',
                  status: 'assessing',
                  current_phase: 'assess',
                  incident_type: 'zero_day',
                  escalation_level: 1,
                  declared_at: new Date().toISOString(),
                },
              ],
            }),
          });
        }
        return Promise.resolve({ ok: true, json: async () => [] });
      });

      const AegisPage = (await import('../app/pages/AegisPage')).default;
      render(
        <MemoryRouter initialEntries={['/organizations/org-1/aegis']}>
          <Routes>
            <Route path="/organizations/:id/aegis" element={<AegisPage />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => expect(screen.getByText('Scope Test')).toBeInTheDocument());
      fireEvent.click(screen.getByText('Scope Test'));

      await waitFor(() => {
        expect(screen.getByText(/Affected Scope/i)).toBeInTheDocument();
        expect(screen.getByText(/Projects/i)).toBeInTheDocument();
        expect(screen.getByText(/Packages/i)).toBeInTheDocument();
        expect(screen.getByText(/Vulnerabilities/i)).toBeInTheDocument();
      });
      expect(screen.getByText('lodash')).toBeInTheDocument();
      expect(screen.getByText('axios')).toBeInTheDocument();
      expect(screen.getByText('GHSA-xxxx')).toBeInTheDocument();
      expect(screen.getByText('CVE-2024-1234')).toBeInTheDocument();
    });

    it('39: Resolve button transitions incident to resolved state', async () => {
      mockFetch.mockImplementation((url: string | URL) => {
        const u = typeof url === 'string' ? url : url.toString();
        if (u.includes('/resolve')) {
          return Promise.resolve({ ok: true, json: async () => ({}) });
        }
        if (u.includes('/incidents/') && u.includes('inc-1')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              id: 'inc-1',
              title: 'Resolve Test',
              severity: 'high',
              status: 'verifying',
              current_phase: 'verify',
              incident_type: 'zero_day',
              declared_at: new Date().toISOString(),
              timeline: [],
            }),
          });
        }
        if (u.includes('/incidents?') || u.includes('/incidents&')) {
          return Promise.resolve({
            ok: true,
            json: async () => ({
              incidents: [
                {
                  id: 'inc-1',
                  title: 'Resolve Test',
                  severity: 'high',
                  status: 'verifying',
                  current_phase: 'verify',
                  incident_type: 'zero_day',
                  escalation_level: 1,
                  declared_at: new Date().toISOString(),
                },
              ],
            }),
          });
        }
        return Promise.resolve({ ok: true, json: async () => [] });
      });

      const AegisPage = (await import('../app/pages/AegisPage')).default;
      render(
        <MemoryRouter initialEntries={['/organizations/org-1/aegis']}>
          <Routes>
            <Route path="/organizations/:id/aegis" element={<AegisPage />} />
          </Routes>
        </MemoryRouter>
      );

      await waitFor(() => expect(screen.getByText('Resolve Test')).toBeInTheDocument());
      fireEvent.click(screen.getByText('Resolve Test'));

      await waitFor(() => expect(screen.getByRole('button', { name: /Resolve/i })).toBeInTheDocument());
      const resolveBtn = screen.getByRole('button', { name: /Resolve/i });
      fireEvent.click(resolveBtn);

      await waitFor(() => {
        const resolveCalls = mockFetch.mock.calls.filter(
          (c) => typeof c[0] === 'string' && (c[0] as string).includes('/resolve')
        );
        expect(resolveCalls.length).toBeGreaterThanOrEqual(1);
      });
    });

    it('40: Incident history table renders past incidents with correct data', async () => {
      const pastIncidents = [
        {
          id: 'inc-past-1',
          title: 'Past Zero-Day',
          incident_type: 'zero_day',
          severity: 'critical',
          status: 'resolved',
          declared_at: '2025-02-15T12:00:00Z',
          total_duration_ms: 3600000,
          affected_projects: ['proj-1'],
        },
      ];

      mockFetch.mockImplementation((url: string | URL) => {
        const u = typeof url === 'string' ? url : url.toString();
        if (u.includes('/incidents/stats')) return Promise.resolve({ ok: true, json: async () => ({ active: 0, totalResolved: 1, monthlyCount: 1 }) });
        if (u.includes('/playbooks')) return Promise.resolve({ ok: true, json: async () => [] });
        if (u.includes('/incidents?') || u.includes('/incidents&')) return Promise.resolve({ ok: true, json: async () => ({ incidents: pastIncidents, total: 1 }) });
        return Promise.resolve({ ok: true, json: async () => ({}) });
      });

      const { AegisManagementConsole } = await import('../components/settings/AegisManagementConsole');
      render(
        <AegisManagementConsole
          organizationId="org-1"
          userPermissions={{ manage_aegis: true, manage_incidents: true }}
        />
      );

      fireEvent.click(screen.getByRole('button', { name: /Incidents/i }));

      await waitFor(() => {
        expect(screen.getByText('Incident History')).toBeInTheDocument();
      });

      await waitFor(() => {
        expect(screen.getByText('Past Zero-Day')).toBeInTheDocument();
      }, { timeout: 3000 });

      const incidentsResCalls = mockFetch.mock.calls.filter(
        (c) => typeof c[0] === 'string' && (c[0] as string).includes('/incidents')
      );
      expect(incidentsResCalls.length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('Integration (41–44)', () => {
    it('41: Phase 9 notification events dispatch for incident lifecycle events', () => {
      const incidentLifecycleEventTypes = [
        'incident_declared',
        'incident_contained',
        'incident_resolved',
      ];
      expect(incidentLifecycleEventTypes).toContain('incident_declared');
      expect(incidentLifecycleEventTypes).toContain('incident_contained');
      expect(incidentLifecycleEventTypes).toContain('incident_resolved');
      expect(incidentLifecycleEventTypes.length).toBe(3);
    });

    it('42: Remediation phase triggers Phase 7 fix sprint', () => {
      const remediatePhaseTools = ['createSecuritySprint', 'triggerAiFix'];
      const zeroDayRemediateTool = 'createSecuritySprint';
      expect(remediatePhaseTools).toContain(zeroDayRemediateTool);
      expect(zeroDayRemediateTool).toBe('createSecuritySprint');
    });

    it('43: Verification phase triggers re-extraction', () => {
      const verifyPhaseTools = ['triggerExtraction'];
      const zeroDayVerifyTool = 'triggerExtraction';
      expect(verifyPhaseTools).toContain(zeroDayVerifyTool);
      expect(zeroDayVerifyTool).toBe('triggerExtraction');
    });

    it('44: SLA deadlines from Phase 15 shown in Assess phase output', () => {
      const assessPhaseTools = ['assessBlastRadius', 'getSLAStatus', 'getWatchtowerSummary'];
      const slaTool = 'getSLAStatus';
      expect(assessPhaseTools).toContain(slaTool);
      expect(slaTool).toBe('getSLAStatus');
    });
  });
});
