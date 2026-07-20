import { embed } from 'ai';
import { supabase } from '../../lib/supabase';
import { getEmbeddingModel } from './provider';

interface MemoryRow {
  category: string;
  key: string;
  content: string;
}

function formatMemories(rows: MemoryRow[]): string {
  return (
    '\n\n## Relevant Organizational Context (from memory)\n' +
    rows.map((m) => `- [${m.category}] ${m.key}: ${m.content}`).join('\n')
  );
}

export async function queryRelevantMemories(
  organizationId: string,
  message: string,
): Promise<string> {
  // Primary path: pgvector cosine similarity via match_aegis_memories RPC.
  try {
    const model = getEmbeddingModel();
    const result = await embed({ model, value: message });

    const { data } = await supabase.rpc('match_aegis_memories', {
      query_embedding: JSON.stringify(result.embedding),
      match_threshold: 0.6,
      match_count: 5,
      filter_org_id: organizationId,
      filter_category: null,
    });

    if (data?.length) return formatMemories(data as MemoryRow[]);
  } catch {
    // Memory retrieval is non-critical — fall through to text search.
  }

  // Fallback: substring search across key + content.
  try {
    const keywords = message.split(/\s+/).slice(0, 3).join('%');
    const { data } = await supabase
      .from('aegis_memory')
      .select('category, key, content')
      .eq('organization_id', organizationId)
      .or(`key.ilike.%${keywords}%,content.ilike.%${keywords}%`)
      .limit(3);

    if (data?.length) return formatMemories(data as MemoryRow[]);
  } catch {
    // Text search also non-critical.
  }

  return '';
}
