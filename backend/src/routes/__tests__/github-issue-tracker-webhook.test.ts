import { queryBuilder, setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

import { handleIssueStateEvent } from '../integrations';

describe('handleIssueStateEvent — GitHub issue close/reopen → tracker link state', () => {
  beforeEach(() => {
    clearTableRegistry();
    jest.clearAllMocks();
  });

  it('flips matching github links to done on close, scoped to the repo', async () => {
    setTableResponse('project_repositories', 'then', { data: [{ project_id: 'p1' }, { project_id: 'p2' }], error: null });
    setTableResponse('finding_tracker_links', 'then', { data: [], error: null });

    await handleIssueStateEvent({
      action: 'closed',
      issue: { number: 7, state: 'closed' },
      repository: { full_name: 'deptex/app' },
    });

    expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({ external_state: 'done' }));
    expect(queryBuilder.eq).toHaveBeenCalledWith('external_id', '7');
    expect(queryBuilder.in).toHaveBeenCalledWith('project_id', ['p1', 'p2']);
  });

  it('flips back to open on reopen', async () => {
    setTableResponse('project_repositories', 'then', { data: [{ project_id: 'p1' }], error: null });
    setTableResponse('finding_tracker_links', 'then', { data: [], error: null });

    await handleIssueStateEvent({
      action: 'reopened',
      issue: { number: 7, state: 'open' },
      repository: { full_name: 'deptex/app' },
    });

    expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({ external_state: 'open' }));
  });

  it('does nothing when no project is connected to the repo', async () => {
    setTableResponse('project_repositories', 'then', { data: [], error: null });

    await handleIssueStateEvent({
      action: 'closed',
      issue: { number: 7, state: 'closed' },
      repository: { full_name: 'unknown/repo' },
    });

    expect(queryBuilder.update).not.toHaveBeenCalled();
  });

  it('ignores malformed payloads', async () => {
    await handleIssueStateEvent({ action: 'closed', issue: {}, repository: {} });
    expect(queryBuilder.update).not.toHaveBeenCalled();
  });
});
