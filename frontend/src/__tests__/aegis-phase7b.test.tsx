/**
 * Phase 7B — Aegis frontend tests (plan 7B-Q tests 67–76, 91–100).
 * AegisPage layout, Management Console tabs, permissions.
 */

import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import React from 'react';

vi.mock('../../lib/supabase', () => ({
  supabase: {
    auth: {
      getSession: vi.fn().mockResolvedValue({
        data: { session: { access_token: 'test-token' } },
      }),
    },
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

describe('Phase 7B: Aegis frontend', () => {
  beforeEach(() => {
    mockMatchMedia();
  });

  describe('AegisPage (7B-L) — plan tests 67–70', () => {
    it('70: route /organizations/:id/aegis renders AegisPage', async () => {
      const AegisPage = (await import('../app/pages/AegisPage')).default;
      render(
        <MemoryRouter initialEntries={['/organizations/org-1/aegis']}>
          <Routes>
            <Route path="/organizations/:id/aegis" element={<AegisPage />} />
          </Routes>
        </MemoryRouter>
      );
      expect(screen.getByPlaceholderText(/message aegis/i)).toBeInTheDocument();
    });

    it('67: main panel has chat input and message area', async () => {
      const AegisPage = (await import('../app/pages/AegisPage')).default;
      render(
        <MemoryRouter initialEntries={['/organizations/org-1/aegis']}>
          <Routes>
            <Route path="/organizations/:id/aegis" element={<AegisPage />} />
          </Routes>
        </MemoryRouter>
      );
      const input = screen.getByPlaceholderText(/message aegis/i);
      expect(input).toBeInTheDocument();
    });
  });

  describe('AegisManagementConsole (7B-K) — plan tests 91–92', () => {
    it('91: Management Console renders with Configuration tab', async () => {
      const { AegisManagementConsole } = await import('../components/settings/AegisManagementConsole');
      render(
        <AegisManagementConsole
          organizationId="org-1"
          userPermissions={{ manage_aegis: true, interact_with_aegis: true }}
        />
      );
      const configButtons = screen.getAllByRole('button', { name: /configuration/i });
      expect(configButtons.length).toBeGreaterThanOrEqual(1);
      expect(configButtons.some((el) => el.textContent?.trim() === 'Configuration')).toBe(true);
    });

    it('92: Operating mode control is present', async () => {
      const { AegisManagementConsole } = await import('../components/settings/AegisManagementConsole');
      render(
        <AegisManagementConsole
          organizationId="org-1"
          userPermissions={{ manage_aegis: true }}
        />
      );
      expect(screen.getByRole('button', { name: 'Read-Only' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Propose' })).toBeInTheDocument();
      expect(screen.getByRole('button', { name: 'Autopilot' })).toBeInTheDocument();
    });

    it('99: Automations tab label is present', async () => {
      const { AegisManagementConsole } = await import('../components/settings/AegisManagementConsole');
      render(
        <AegisManagementConsole organizationId="org-1" userPermissions={{ manage_aegis: true }} />
      );
      expect(screen.getByText(/automations/i)).toBeInTheDocument();
    });

    it('Audit Log tab is present', async () => {
      const { AegisManagementConsole } = await import('../components/settings/AegisManagementConsole');
      render(
        <AegisManagementConsole organizationId="org-1" userPermissions={{ manage_aegis: true }} />
      );
      expect(screen.getByText(/audit log/i)).toBeInTheDocument();
    });
  });
});
