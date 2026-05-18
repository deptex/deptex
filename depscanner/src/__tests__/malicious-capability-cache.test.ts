/**
 * Verifies the package_capabilities cache read + upsert path.
 *
 * The full pipeline-level "unpack-once-share" assertions require a real
 * unpacked tarball + GuardDog binary, which lives in the smoke test. This
 * suite covers the contract the pipeline depends on: read maps DB rows
 * into a CapabilitySet and upsert serializes every flag onto the row.
 */
import {
  readCapabilityCache,
  upsertCapabilityCache,
  type CapabilityCacheRow,
} from '../malicious/insert-finding';
import { CAPABILITY_KEYS } from '../malicious/capabilities/types';

describe('readCapabilityCache', () => {
  it('returns the row mapped into a CapabilitySet on cache hit', async () => {
    const row = {
      package_name: 'evil',
      version: '1.0.0',
      ecosystem: 'npm',
      scanner_version: 'capability@v2.0.0',
      scan_error: null,
      spawns_processes: true,
      network_io: true,
      eval_dynamic: false,
      native_addon_load: false,
      filesystem_write: true,
      crypto_operations: false,
      serialization_deser: false,
      install_script: true,
      dns_query: false,
      websocket: false,
      process_signal: false,
      encrypted_payload: false,
      dynamic_import: false,
      reads_env: true,
      clipboard_access: false,
    };

    const fakeStorage = {
      from: () => ({
        select: () => ({
          eq: () => ({
            eq: () => ({
              eq: () => ({
                maybeSingle: async () => ({ data: row, error: null }),
              }),
            }),
          }),
        }),
      }),
    } as unknown as Parameters<typeof readCapabilityCache>[0];

    const result = await readCapabilityCache(fakeStorage, 'evil', '1.0.0', 'npm');
    expect(result).not.toBeNull();
    expect(result!.scanner_version).toBe('capability@v2.0.0');
    expect(result!.capabilities.spawns_processes).toBe(true);
    expect(result!.capabilities.eval_dynamic).toBe(false);
    expect(result!.capabilities.install_script).toBe(true);
    expect(result!.capabilities.reads_env).toBe(true);
  });

  it('returns null on cache miss', async () => {
    const fakeStorage = {
      from: () => ({
        select: () => ({
          eq: () => ({
            eq: () => ({
              eq: () => ({
                maybeSingle: async () => ({ data: null, error: null }),
              }),
            }),
          }),
        }),
      }),
    } as unknown as Parameters<typeof readCapabilityCache>[0];

    const result = await readCapabilityCache(fakeStorage, 'missing', '0.0.1', 'npm');
    expect(result).toBeNull();
  });

  it('returns null on DB error', async () => {
    const fakeStorage = {
      from: () => ({
        select: () => ({
          eq: () => ({
            eq: () => ({
              eq: () => ({
                maybeSingle: async () => ({ data: null, error: { message: 'boom' } }),
              }),
            }),
          }),
        }),
      }),
    } as unknown as Parameters<typeof readCapabilityCache>[0];

    const result = await readCapabilityCache(fakeStorage, 'x', '1.0.0', 'npm');
    expect(result).toBeNull();
  });
});

describe('upsertCapabilityCache', () => {
  it('writes every CAPABILITY_KEYS flag onto the upsert payload', async () => {
    let captured: { payload: Record<string, unknown> | null; opts: unknown } = {
      payload: null,
      opts: null,
    };

    const fakeStorage = {
      from: () => ({
        upsert: (payload: Record<string, unknown>, opts: unknown) => {
          captured.payload = payload;
          captured.opts = opts;
          return Promise.resolve({ error: null });
        },
      }),
    } as unknown as Parameters<typeof upsertCapabilityCache>[0];

    const row: CapabilityCacheRow = {
      package_name: 'evil',
      version: '1.0.0',
      ecosystem: 'npm',
      scanner_version: 'capability@v2.0.0',
      scan_error: null,
      capabilities: {
        spawns_processes: true,
        network_io: true,
        eval_dynamic: false,
        native_addon_load: false,
        filesystem_write: false,
        crypto_operations: false,
        serialization_deser: false,
        install_script: true,
        dns_query: false,
        websocket: false,
        process_signal: false,
        encrypted_payload: false,
        dynamic_import: false,
        reads_env: false,
        clipboard_access: false,
      },
    };

    await upsertCapabilityCache(fakeStorage, row);
    expect(captured.payload).not.toBeNull();
    for (const k of CAPABILITY_KEYS) {
      expect(captured.payload).toHaveProperty(k);
    }
    expect(captured.payload!.package_name).toBe('evil');
    expect(captured.payload!.version).toBe('1.0.0');
    expect(captured.payload!.ecosystem).toBe('npm');
    expect(captured.payload!.scanner_version).toBe('capability@v2.0.0');
    expect(captured.payload!.scan_error).toBeNull();
    expect(captured.opts).toEqual({ onConflict: 'package_name,version,ecosystem' });
  });
});
