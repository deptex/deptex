import { queryBuilder, setTableResponse, clearTableRegistry } from '../../test/mocks/supabaseSingleton';

jest.mock('../../lib/supabase', () => ({
  ...require('../../test/mocks/supabaseSingleton'),
  createUserClient: jest.fn(),
}));

import { handleIssueStateEvent, handleLinearIssueEvent, handleJiraIssueEvent } from '../integrations';

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

describe('handleLinearIssueEvent — Linear webhook → tracker link state', () => {
  beforeEach(() => {
    clearTableRegistry();
    jest.clearAllMocks();
  });

  it('marks a completed Linear issue as done, matched by issue id', async () => {
    await handleLinearIssueEvent({ type: 'Issue', action: 'update', data: { id: 'lin-1', state: { type: 'completed' } } });
    expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({ external_state: 'done' }));
    expect(queryBuilder.eq).toHaveBeenCalledWith('external_id', 'lin-1');
  });

  it('marks a started Linear issue as open', async () => {
    await handleLinearIssueEvent({ type: 'Issue', action: 'update', data: { id: 'lin-1', state: { type: 'started' } } });
    expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({ external_state: 'open' }));
  });

  it('ignores non-Issue events', async () => {
    await handleLinearIssueEvent({ type: 'Comment', action: 'create', data: { id: 'c-1' } });
    expect(queryBuilder.update).not.toHaveBeenCalled();
  });

  it('ignores payloads without a state', async () => {
    await handleLinearIssueEvent({ type: 'Issue', action: 'update', data: { id: 'lin-1' } });
    expect(queryBuilder.update).not.toHaveBeenCalled();
  });
});

describe('handleJiraIssueEvent — Jira webhook → tracker link state', () => {
  beforeEach(() => {
    clearTableRegistry();
    jest.clearAllMocks();
  });

  it('marks a done-category Jira issue as done, scoped by org + issue id', async () => {
    await handleJiraIssueEvent('org-1', { issue: { id: '10001', fields: { status: { statusCategory: { key: 'done' } } } } });
    expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({ external_state: 'done' }));
    expect(queryBuilder.eq).toHaveBeenCalledWith('organization_id', 'org-1');
    expect(queryBuilder.eq).toHaveBeenCalledWith('external_id', '10001');
  });

  it('marks an in-progress Jira issue as open', async () => {
    await handleJiraIssueEvent('org-1', { issue: { id: '10001', fields: { status: { statusCategory: { key: 'indeterminate' } } } } });
    expect(queryBuilder.update).toHaveBeenCalledWith(expect.objectContaining({ external_state: 'open' }));
  });

  it('ignores payloads missing the status category', async () => {
    await handleJiraIssueEvent('org-1', { issue: { id: '10001', fields: {} } });
    expect(queryBuilder.update).not.toHaveBeenCalled();
  });
});
