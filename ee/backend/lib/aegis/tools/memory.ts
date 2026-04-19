import { tool } from 'ai';
import { z } from 'zod';
import { registerAegisTool } from './registry';
import { supabase } from '../../../../../backend/src/lib/supabase';

registerAegisTool('storeMemory', {
  category: 'memory',
  permissionLevel: 'safe',
  requiredRbacPermissions: [],
}, tool({
  description: 'Store a piece of knowledge, decision, preference, or outcome in long-term memory for future retrieval. Use this to remember important organizational context.',
  parameters: z.object({
    organizationId: z.string().uuid(),
    category: z.enum(['decision', 'preference', 'knowledge', 'outcome', 'note']),
    key: z.string().describe('Short descriptive key for this memory'),
    content: z.string().describe('The full content to remember'),
    threadId: z.string().uuid().optional(),
    userId: z.string().uuid().optional(),
  }),
  execute: async ({ organizationId, category, key, content, threadId, userId }) => {
    try {
      let embedding: number[] | null = null;
      try {
        const { getEmbeddingModel } = await import('../llm-provider');
        const { embed } = await import('ai');
        const model = getEmbeddingModel();
        const result = await embed({ model, value: content });
        embedding = result.embedding as unknown as number[];
      } catch (embErr) {
        console.warn('[Aegis Memory] Embedding generation failed, storing without vector:', embErr);
      }

      const insertData: any = {
        organization_id: organizationId,
        category,
        key,
        content,
        source_thread_id: threadId || null,
        created_by: userId || null,
      };
      if (embedding) {
        insertData.embedding = JSON.stringify(embedding);
      }

      const { data, error } = await supabase
        .from('aegis_memory')
        .insert(insertData)
        .select('id, key, category, created_at')
        .single();

      if (error) throw error;
      return JSON.stringify({ success: true, memory: data });
    } catch (err: any) {
      return JSON.stringify({ error: err.message });
    }
  },
}));

registerAegisTool('queryMemory', {
  category: 'memory',
  permissionLevel: 'safe',
  requiredRbacPermissions: [],
}, tool({
  description: 'Search organizational memory for relevant context. Returns the most relevant memories based on semantic similarity to the query.',
  parameters: z.object({
    organizationId: z.string().uuid(),
    query: z.string().describe('Natural language query to search memories'),
    category: z.enum(['decision', 'preference', 'knowledge', 'outcome', 'note']).optional(),
    limit: z.number().min(1).max(20).default(5),
  }),
  execute: async ({ organizationId, query, category, limit }) => {
    try {
      let memories: any[] = [];

      try {
        const { getEmbeddingModel } = await import('../llm-provider');
        const { embed } = await import('ai');
        const model = getEmbeddingModel();
        const result = await embed({ model, value: query });
        const embedding = result.embedding;

        const { data, error } = await supabase.rpc('match_aegis_memories', {
          query_embedding: JSON.stringify(embedding),
          match_threshold: 0.5,
          match_count: limit,
          filter_org_id: organizationId,
          filter_category: category || null,
        });

        if (!error && data?.length) {
          memories = data;
        }
      } catch {
        // Fallback: text search if vector search fails
      }

      if (!memories.length) {
        let q = supabase
          .from('aegis_memory')
          .select('id, category, key, content, created_at, metadata')
          .eq('organization_id', organizationId)
          .or(`key.ilike.%${query}%,content.ilike.%${query}%`)
          .order('created_at', { ascending: false })
          .limit(limit);

        if (category) q = q.eq('category', category);

        const { data } = await q;
        memories = data || [];
      }

      // Filter expired
      const now = new Date().toISOString();
      memories = memories.filter(m => !m.expires_at || m.expires_at > now);

      return JSON.stringify({
        count: memories.length,
        memories: memories.map(m => ({
          id: m.id,
          category: m.category,
          key: m.key,
          content: m.content,
          created_at: m.created_at,
          similarity: m.similarity,
        })),
      });
    } catch (err: any) {
      return JSON.stringify({ error: err.message, memories: [] });
    }
  },
}));

registerAegisTool('listMemories', {
  category: 'memory',
  permissionLevel: 'safe',
  requiredRbacPermissions: [],
}, tool({
  description: 'List all stored memories for the organization, optionally filtered by category.',
  parameters: z.object({
    organizationId: z.string().uuid(),
    category: z.enum(['decision', 'preference', 'knowledge', 'outcome', 'note']).optional(),
    limit: z.number().min(1).max(100).default(20),
    offset: z.number().min(0).default(0),
  }),
  execute: async ({ organizationId, category, limit, offset }) => {
    try {
      let q = supabase
        .from('aegis_memory')
        .select('id, category, key, content, created_at, created_by, metadata', { count: 'exact' })
        .eq('organization_id', organizationId)
        .order('created_at', { ascending: false })
        .range(offset, offset + limit - 1);

      if (category) q = q.eq('category', category);

      const { data, count, error } = await q;
      if (error) throw error;

      return JSON.stringify({
        total: count || 0,
        memories: (data || []).map(m => ({
          id: m.id,
          category: m.category,
          key: m.key,
          content: m.content,
          created_at: m.created_at,
        })),
      });
    } catch (err: any) {
      return JSON.stringify({ error: err.message });
    }
  },
}));
