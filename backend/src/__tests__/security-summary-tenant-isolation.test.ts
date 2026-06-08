import express from 'express';
import request from 'supertest';
import {
  setTableResponse,
  clearTableRegistry,
  clearRpcRegistry,
} from '../test/mocks/supabaseSingleton';

// Regression coverage for the cross-org IDOR + team-access-gate fixes on the team
// security-summary endpoint (checkTeamAccess now validates team -> org and gates on team access).

const ORG = '00000000-0000-0000-0000-00000000000a';
const TEAM = '00000000-0000-0000-0000-0000000000c1';
const USER = '00000000-0000-0000-0000-000000000099';

jest.mock('../middleware/auth', () => ({
  authenticateUser: (req: any, _res: any, next: any) => {
    req.user = { id: USER };
    next();
  },
}));

import teamsRouter from '../routes/teams';

const app = express();
app.use(express.json());
app.use('/api/organizations', teamsRouter);

const url = `/api/organizations/${ORG}/teams/${TEAM}/security-summary`;

describe('team security-summary — tenant isolation + access gate', () => {
  beforeEach(() => {
    clearTableRegistry();
    clearRpcRegistry();
  });

  it('404s when the caller is not a member of the organization', async () => {
    setTableResponse('organization_members', 'single', {
      data: null,
      error: { message: 'not found', code: 'PGRST116' },
    });
    const res = await request(app).get(url);
    expect(res.status).toBe(404);
  });

  it('404s when the teamId belongs to a different organization (cross-org IDOR)', async () => {
    // Caller IS a member of the org in the path, but the team does not belong to it.
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('teams', 'single', {
      data: null,
      error: { message: 'not found', code: 'PGRST116' },
    });
    const res = await request(app).get(url);
    expect(res.status).toBe(404);
  });

  it('403s for an org member who is not on the team and lacks view-all permission', async () => {
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('teams', 'single', { data: { id: TEAM }, error: null });
    setTableResponse('team_members', 'single', { data: null, error: null });
    setTableResponse('organization_roles', 'single', { data: { permissions: {} }, error: null });
    const res = await request(app).get(url);
    expect(res.status).toBe(403);
  });

  it('grants access to a team member', async () => {
    setTableResponse('organization_members', 'single', { data: { role: 'member' }, error: null });
    setTableResponse('teams', 'single', { data: { id: TEAM }, error: null });
    setTableResponse('team_members', 'single', { data: { role_id: 'r1' }, error: null });
    const res = await request(app).get(url);
    expect(res.status).toBe(200);
  });
});
