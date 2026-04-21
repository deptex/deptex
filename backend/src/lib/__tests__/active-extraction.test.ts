import { getActiveExtractionId } from '../active-extraction';

type MockChain = {
  from: jest.Mock;
  select: jest.Mock;
  eq: jest.Mock;
  single: jest.Mock;
};

function makeMock(response: { data: unknown; error: unknown }): { supabase: any; chain: MockChain } {
  const chain: MockChain = {
    from: jest.fn().mockReturnThis(),
    select: jest.fn().mockReturnThis(),
    eq: jest.fn().mockReturnThis(),
    single: jest.fn().mockResolvedValue(response),
  };
  return { supabase: chain as any, chain };
}

describe('getActiveExtractionId', () => {
  it('returns the active extraction_run_id for a project', async () => {
    const { supabase, chain } = makeMock({
      data: { active_extraction_run_id: 'run_abc' },
      error: null,
    });

    const result = await getActiveExtractionId(supabase, 'proj-1');

    expect(result).toBe('run_abc');
    expect(chain.from).toHaveBeenCalledWith('projects');
    expect(chain.select).toHaveBeenCalledWith('active_extraction_run_id');
    expect(chain.eq).toHaveBeenCalledWith('id', 'proj-1');
  });

  it('returns null when the project row has active_extraction_run_id = NULL', async () => {
    const { supabase } = makeMock({
      data: { active_extraction_run_id: null },
      error: null,
    });

    const result = await getActiveExtractionId(supabase, 'proj-1');
    expect(result).toBeNull();
  });

  it('returns null when the query errors (project not found, RLS, etc.)', async () => {
    const { supabase } = makeMock({
      data: null,
      error: { code: 'PGRST116', message: 'No rows found' },
    });

    const result = await getActiveExtractionId(supabase, 'does-not-exist');
    expect(result).toBeNull();
  });

  it('returns null when data is missing entirely', async () => {
    const { supabase } = makeMock({ data: null, error: null });

    const result = await getActiveExtractionId(supabase, 'proj-1');
    expect(result).toBeNull();
  });
});
