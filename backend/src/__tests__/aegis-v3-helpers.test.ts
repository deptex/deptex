import {
  setTableResponse,
  clearTableRegistry,
  setRpcResponse,
  clearRpcRegistry,
  supabase,
} from '../test/mocks/supabaseSingleton';

import {
  buildSDKTool,
  type AegisToolEntry,
  type AegisToolContext,
} from '../lib/aegis-v3/tool-types';
import { ALL_AEGIS_TOOLS, buildToolSet } from '../lib/aegis-v3/tools';
import { buildAegisSystemPrompt } from '../lib/aegis-v3/system-prompt';
import { getOrCreateThread, loadThreadHistory } from '../lib/aegis-v3/thread';
import { queryRelevantMemories } from '../lib/aegis-v3/memory';

const ORG_ID = '00000000-0000-0000-0000-000000000001';
const USER_ID = '00000000-0000-0000-0000-000000000099';
const THREAD_ID = '00000000-0000-0000-0000-0000000000aa';

function makeCtx(): AegisToolContext {
  return {
    orgId: ORG_ID,
    userId: USER_ID,
    threadId: THREAD_ID,
    operatingMode: 'propose',
    supabase: supabase as unknown as AegisToolContext['supabase'],
  };
}

describe('aegis-v3 helpers', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
  });

  describe('provider re-exports', () => {
    it('exposes the v1 BYOK loaders unchanged', async () => {
      const provider = await import('../lib/aegis-v3/provider');
      expect(typeof provider.getLanguageModelForOrg).toBe('function');
      expect(typeof provider.getProviderInfoForOrg).toBe('function');
      expect(typeof provider.getEmbeddingModel).toBe('function');
    });
  });

  describe('tool registry', () => {
    it('aggregates the per-category tool arrays', () => {
      const names = ALL_AEGIS_TOOLS.map((t) => t.name);
      expect(names).toContain('list_projects');
      expect(names).toContain('list_policies');
      expect(ALL_AEGIS_TOOLS.length).toBeGreaterThan(0);
    });

    it('buildToolSet returns a record keyed by tool name', () => {
      const set = buildToolSet(makeCtx());
      expect(Object.keys(set).sort()).toEqual(ALL_AEGIS_TOOLS.map((t) => t.name).sort());
    });

    it('buildSDKTool produces a Tool with description and inputSchema', () => {
      const entry: AegisToolEntry<{ foo: string }, { ok: true }> = {
        name: 'noop',
        description: 'A no-op tool',
        inputSchema: {
          jsonSchema: { type: 'object', properties: {}, additionalProperties: false },
        } as any,
        execute: async () => ({ ok: true }),
      };
      const t = buildSDKTool(entry, makeCtx()) as any;
      expect(t).toBeDefined();
      expect(t.description).toBe('A no-op tool');
      expect(typeof t.execute).toBe('function');
    });

    it('buildSDKTool returns a permission-denied error when caller lacks permission', async () => {
      setTableResponse('organization_members', 'single', {
        data: { role: 'viewer' },
        error: null,
      });
      setTableResponse('organization_roles', 'single', {
        data: { permissions: { interact_with_aegis: false } },
        error: null,
      });

      const entry: AegisToolEntry<Record<string, never>, { ran: true }> = {
        name: 'gated',
        description: 'gated tool',
        inputSchema: {
          jsonSchema: { type: 'object', properties: {}, additionalProperties: false },
        } as any,
        permission: 'interact_with_aegis',
        execute: async () => ({ ran: true }),
      };
      const t = buildSDKTool(entry, makeCtx()) as any;
      const result = await t.execute({}, { toolCallId: 'tc1', messages: [] });
      expect(result).toEqual({ error: 'Missing permission: interact_with_aegis' });
    });

    it('buildSDKTool runs the entry execute when caller has permission', async () => {
      setTableResponse('organization_members', 'single', {
        data: { role: 'owner' },
        error: null,
      });
      setTableResponse('organization_roles', 'single', {
        data: { permissions: { interact_with_aegis: true } },
        error: null,
      });

      const entry: AegisToolEntry<{ q: string }, { echoed: string }> = {
        name: 'echo',
        description: 'echo',
        inputSchema: {
          jsonSchema: {
            type: 'object',
            properties: { q: { type: 'string' } },
            required: ['q'],
          },
        } as any,
        permission: 'interact_with_aegis',
        execute: async (input) => ({ echoed: input.q }),
      };
      const t = buildSDKTool(entry, makeCtx()) as any;
      const result = await t.execute({ q: 'hi' }, { toolCallId: 'tc2', messages: [] });
      expect(result).toEqual({ echoed: 'hi' });
    });
  });

  describe('buildAegisSystemPrompt', () => {
    it('embeds the org name and the never-invent-IDs guardrail', () => {
      const out = buildAegisSystemPrompt({
        orgName: 'Acme',
        organizationId: ORG_ID,
      });
      expect(out).toContain('Acme');
      expect(out).toContain('must not invent or pass UUIDs');
      expect(out).toContain('Use names, never IDs');
    });

    it('appends a project context section when projectId is set', () => {
      const out = buildAegisSystemPrompt({
        orgName: 'Acme',
        organizationId: ORG_ID,
        context: { projectId: 'proj-123' },
      });
      expect(out).toContain('Current context: project');
    });
  });

  describe('thread helpers', () => {
    it('returns the existing threadId and bumps updated_at when threadId is passed', async () => {
      setTableResponse('aegis_chat_threads', 'then', { data: null, error: null });
      const out = await getOrCreateThread(ORG_ID, USER_ID, THREAD_ID, 'hello', undefined);
      expect(out).toBe(THREAD_ID);
    });

    it('inserts a new thread when threadId is undefined', async () => {
      setTableResponse('aegis_chat_threads', 'single', {
        data: { id: 'new-thread-id' },
        error: null,
      });
      const out = await getOrCreateThread(ORG_ID, USER_ID, undefined, 'first message', {
        type: 'project',
        id: 'p1',
        projectId: 'p1',
      });
      expect(out).toBe('new-thread-id');
    });

    it('loadThreadHistory returns user/assistant ModelMessages', async () => {
      setTableResponse('aegis_chat_messages', 'then', {
        data: [
          { role: 'user', content: 'hi' },
          { role: 'assistant', content: 'hello' },
        ],
        error: null,
      });
      const out = await loadThreadHistory(THREAD_ID);
      expect(out).toEqual([
        { role: 'user', content: 'hi' },
        { role: 'assistant', content: 'hello' },
      ]);
    });
  });

  describe('queryRelevantMemories', () => {
    it('returns empty string when neither vector nor text search yields rows', async () => {
      setRpcResponse('match_aegis_memories', { data: null, error: null });
      setTableResponse('aegis_memory', 'then', { data: [], error: null });
      const out = await queryRelevantMemories(ORG_ID, 'find vulns');
      expect(out).toBe('');
    });
  });
});
