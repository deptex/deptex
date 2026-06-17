import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, waitFor } from '../../test/utils';
import { CapabilitiesSection } from '../CapabilitiesSection';
import type { PackageCapabilities } from '../../lib/api';

vi.mock('../../lib/api', () => ({
  api: {
    capabilities: {
      fetch: vi.fn(),
    },
  },
}));

import { api } from '../../lib/api';

const ALL_FALSE = {
  spawns_processes: false,
  network_io: false,
  eval_dynamic: false,
  native_addon_load: false,
  filesystem_write: false,
  crypto_operations: false,
  serialization_deser: false,
  install_script: false,
  dns_query: false,
  websocket: false,
  process_signal: false,
  encrypted_payload: false,
  dynamic_import: false,
  reads_env: false,
  clipboard_access: false,
};

function rowWith(overrides: Partial<PackageCapabilities['capabilities']>): PackageCapabilities {
  return {
    package_name: 'evil',
    version: '1.0.0',
    ecosystem: 'npm',
    scanner_version: 'capability@v2.0.0',
    scanned_at: '2026-05-05T12:00:00Z',
    scan_error: null,
    capabilities: { ...ALL_FALSE, ...overrides },
  };
}

beforeEach(() => {
  vi.clearAllMocks();
});

describe('CapabilitiesSection', () => {
  it('renders chips for each true capability', async () => {
    (api.capabilities.fetch as any).mockResolvedValue(
      rowWith({ spawns_processes: true, network_io: true, install_script: true }),
    );

    render(
      <CapabilitiesSection
        organizationId="org-1"
        ecosystem="npm"
        packageName="evil"
        version="1.0.0"
      />,
    );

    await waitFor(() => {
      expect(screen.getByText('Spawns processes')).toBeInTheDocument();
    });
    expect(screen.getByText('Network I/O')).toBeInTheDocument();
    expect(screen.getByText('Install script')).toBeInTheDocument();
    // false capabilities should not render
    expect(screen.queryByText('Reads environment')).not.toBeInTheDocument();
  });

  it('renders empty-state caption when no capabilities are true', async () => {
    (api.capabilities.fetch as any).mockResolvedValue(rowWith({}));

    render(
      <CapabilitiesSection
        organizationId="org-1"
        ecosystem="npm"
        packageName="boring"
        version="1.0.0"
      />,
    );

    await waitFor(() => {
      expect(screen.getByText('No notable capabilities detected')).toBeInTheDocument();
    });
  });

  it('renders "Capability scan pending" when 404', async () => {
    (api.capabilities.fetch as any).mockRejectedValue(new Error('HTTP 404 not found'));

    render(
      <CapabilitiesSection
        organizationId="org-1"
        ecosystem="npm"
        packageName="never"
        version="0.0.1"
      />,
    );

    await waitFor(() => {
      expect(screen.getByText('Capability scan pending')).toBeInTheDocument();
    });
  });

  it('renders "Capability scan unavailable" when scan_error is non-null', async () => {
    (api.capabilities.fetch as any).mockResolvedValue({
      ...rowWith({ spawns_processes: true }),
      scan_error: 'tree-sitter wasm load failed',
    });

    render(
      <CapabilitiesSection
        organizationId="org-1"
        ecosystem="npm"
        packageName="broken"
        version="1.0.0"
      />,
    );

    await waitFor(() => {
      expect(screen.getByText('Capability scan unavailable')).toBeInTheDocument();
    });
    // Failed scans should NOT render any chips even if the row claims flags are true
    expect(screen.queryByText('Spawns processes')).not.toBeInTheDocument();
  });

  it('renders "scan pending" when ecosystem is null', async () => {
    render(
      <CapabilitiesSection
        organizationId="org-1"
        ecosystem={null}
        packageName="x"
        version="1.0.0"
      />,
    );
    await waitFor(() => {
      expect(screen.getByText('Capability scan pending')).toBeInTheDocument();
    });
    expect(api.capabilities.fetch).not.toHaveBeenCalled();
  });
});
