import { queryBuilder, setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

import { syncOrgTrackerLinkStates } from '../trackers';

const ORG = 'org-1';

function mockLinearState(type: string) {
  (global as any).fetch = jest.fn().mockResolvedValue({
    ok: true,
    json: async () => ({ data: { issue: { state: { type } } } }),
  });
}

describe('syncOrgTrackerLinkStates — Linear poll', () => {
  beforeEach(() => {
    clearTableRegistry();
    jest.clearAllMocks();
    setTableResponse('organization_integrations', 'maybeSingle', {
      data: { access_token: 'lin_tok', metadata: {} },
      error: null,
    });
  });

  it('marks a completed Linear issue as done', async () => {
    setTableResponse('finding_tracker_links', 'then', {
      data: [{ id: 'l1', project_id: 'p1', provider: 'linear', external_id: 'lin-uuid-1', external_state: 'open' }],
      error: null,
    });
    mockLinearState('completed');

    const changed = await syncOrgTrackerLinkStates(ORG);

    expect(changed).toBe(1);
    expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({ external_state: 'done' }));
  });

  it('treats a canceled Linear issue as done', async () => {
    setTableResponse('finding_tracker_links', 'then', {
      data: [{ id: 'l1', project_id: 'p1', provider: 'linear', external_id: 'lin-uuid-1', external_state: 'open' }],
      error: null,
    });
    mockLinearState('canceled');

    expect(await syncOrgTrackerLinkStates(ORG)).toBe(1);
    expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({ external_state: 'done' }));
  });

  it('does not rewrite an unchanged state (started stays open)', async () => {
    setTableResponse('finding_tracker_links', 'then', {
      data: [{ id: 'l1', project_id: 'p1', provider: 'linear', external_id: 'lin-uuid-1', external_state: 'open' }],
      error: null,
    });
    mockLinearState('started');

    expect(await syncOrgTrackerLinkStates(ORG)).toBe(0);
    expect(queryBuilder.update).not.toHaveBeenCalled();
  });
});
