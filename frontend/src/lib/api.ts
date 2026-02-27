import { supabase } from './supabase';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';

const REPOS_CACHE_TTL_MS = 5 * 60 * 1000;
const SCAN_CACHE_TTL_MS = 5 * 60 * 1000;

export interface Organization {
  id: string;
  name: string;
  plan: string;
  created_at: string;
  updated_at: string;
  role?: string;
  role_display_name?: string | null;
  role_color?: string | null;
  user_rank?: number | null;
  permissions?: RolePermissions;
  member_count?: number;
  avatar_url?: string | null;
  github_installation_id?: string | null;
  get_started_dismissed?: boolean;
}

export interface RolePermissions {
  view_settings: boolean;
  manage_billing: boolean;
  manage_security?: boolean;
  view_activity: boolean;
  manage_compliance: boolean;
  interact_with_security_agent: boolean;
  manage_aegis: boolean;
  view_members: boolean;
  add_members: boolean;
  edit_roles: boolean;
  edit_permissions: boolean;
  kick_members: boolean;
  manage_teams_and_projects: boolean;
  manage_integrations: boolean;
  manage_notifications?: boolean;
  view_overview?: boolean;
  view_all_teams_and_projects?: boolean;
}

export interface OrganizationRole {
  id: string;
  organization_id: string;
  name: string;
  display_name?: string | null;
  color?: string | null;
  is_default: boolean;
  display_order: number;
  permissions?: RolePermissions;
  created_at: string;
  updated_at: string;
}

export interface Integration {
  provider: string;
  team_name?: string;
  provider_username?: string;
  created_at: string;
  updated_at: string;
}

export interface OrganizationIntegration {
  id: string;
  organization_id: string;
  provider: 'github' | 'gitlab' | 'bitbucket' | 'slack' | 'discord' | 'jira';
  installation_id?: string | null;
  display_name?: string | null;
  access_token?: string | null;
  refresh_token?: string | null;
  webhook_secret?: string | null;
  metadata?: Record<string, any>;
  status: 'connected' | 'disconnected' | 'error';
  connected_at: string;
  last_sync_at?: string | null;
  created_at: string;
  updated_at: string;
}

export type CiCdProvider = 'github' | 'gitlab' | 'bitbucket' | 'slack' | 'discord' | 'jira' | 'linear' | 'asana' | 'custom_notification' | 'custom_ticketing' | 'email';

export interface CiCdConnection {
  id: string;
  organization_id?: string;
  project_id?: string;
  provider: CiCdProvider;
  installation_id?: string | null;
  display_name?: string | null;
  metadata?: Record<string, any>;
  status: 'connected' | 'disconnected' | 'error';
  connected_at: string;
  created_at: string;
  updated_at: string;
}

export interface RepoWithProvider {
  id: number;
  full_name: string;
  default_branch: string;
  private: boolean;
  framework: string;
  ecosystem?: string;
  provider?: CiCdProvider;
  integration_id?: string;
  display_name?: string;
}

export interface OrganizationInvitation {
  id: string;
  organization_id: string;
  organization_name?: string;
  email: string;
  role: string;
  status: string;
  created_at: string;
  expires_at: string;
  team_id?: string | null;
  team_name?: string | null;
  team_ids?: string[];
  team_names?: string[];
}

export interface OrganizationMember {
  user_id: string;
  role: string;
  role_display_name?: string | null;
  role_color?: string | null;
  rank?: number | null;
  created_at: string;
  email: string;
  full_name?: string;
  avatar_url?: string | null;
  teams?: Array<{ id: string; name: string }>;
}

async function getAuthToken(): Promise<string | null> {
  const { data: { session }, error } = await supabase.auth.getSession();

  if (error) {
    console.error('Error getting session:', error);
    return null;
  }

  if (session) {
    const expiresAt = session.expires_at;
    if (expiresAt) {
      const expiresIn = expiresAt - Math.floor(Date.now() / 1000);
      if (expiresIn < 300) {
        console.log('Token expiring soon, refreshing...');
        const { data: { session: refreshedSession }, error: refreshError } = await supabase.auth.refreshSession();
        if (!refreshError && refreshedSession) {
          return refreshedSession.access_token;
        }
      }
    }
    return session.access_token;
  }

  return null;
}

async function fetchWithAuth(url: string, options: RequestInit = {}) {
  const token = await getAuthToken();

  if (!token) {
    throw new Error('Not authenticated');
  }

  const headers = new Headers();
  headers.set('Authorization', `Bearer ${token}`);
  headers.set('Content-Type', 'application/json');

  if (options.headers) {
    const existingHeaders = new Headers(options.headers);
    existingHeaders.forEach((value, key) => {
      headers.set(key, value);
    });
  }

  const response = await fetch(`${API_BASE_URL}${url}`, {
    ...options,
    headers,
    credentials: 'include',
  });

  if (!response.ok) {
    const error = await response.json().catch(() => ({ error: 'Unknown error' }));
    throw new Error(error.error || `HTTP error! status: ${response.status}`);
  }

  if (response.status === 204) {
    return undefined;
  }

  return response.json();
}

export const api = {
  _orgDataCache: new Map<string, Organization>(),
  _orgPrefetchCache: new Map<string, Promise<Organization>>(),
  _dependencyDataCache: new Map<string, ProjectDependency>(),

  // Dependency tab prefetch caches (keyed by "orgId:projectId:depId")
  _depOverviewPrefetchCache: new Map<string, Promise<[any, ProjectEffectivePolicies | null]>>(),
  _supplyChainPrefetchCache: new Map<string, Promise<[SupplyChainResponse, ProjectEffectivePolicies | null]>>(),
  _watchtowerPrefetchCache: new Map<string, Promise<[WatchtowerSummary | null, WatchtowerCommitsResponse]>>(),
  _notesPrefetchCache: new Map<string, Promise<{ notes: DependencyNote[] }>>(),

  async getOrganizations(): Promise<Organization[]> {
    const orgs = await fetchWithAuth('/api/organizations');
    orgs.forEach((org: Organization) => {
      this._orgDataCache.set(org.id, org);
    });
    return orgs;
  },

  async createOrganization(name: string): Promise<Organization> {
    const org = await fetchWithAuth('/api/organizations', {
      method: 'POST',
      body: JSON.stringify({ name }),
    });
    this._orgDataCache.set(org.id, org);
    return org;
  },

  getCachedOrganization(id: string): Organization | null {
    return this._orgDataCache.get(id) || null;
  },

  async getOrganization(id: string, useCache = true): Promise<Organization> {
    if (useCache && this._orgPrefetchCache.has(id)) {
      const cachedPromise = this._orgPrefetchCache.get(id)!;
      this._orgPrefetchCache.delete(id);
      const org = await cachedPromise;
      this._orgDataCache.set(id, org);
      return org;
    }

    const org = await fetchWithAuth(`/api/organizations/${id}`);
    this._orgDataCache.set(id, org);
    return org;
  },

  async prefetchOrganization(id: string): Promise<void> {
    if (!this._orgPrefetchCache.has(id)) {
      const promise = fetchWithAuth(`/api/organizations/${id}`).then((org) => {
        this._orgDataCache.set(id, org);
        return org;
      }).catch(() => {
        this._orgPrefetchCache.delete(id);
        throw new Error('Failed to prefetch organization');
      });
      this._orgPrefetchCache.set(id, promise);
    }
  },

  async getIntegrations(): Promise<Integration[]> {
    return fetchWithAuth('/api/integrations');
  },

  async disconnectIntegration(provider: string): Promise<void> {
    return fetchWithAuth(`/api/integrations/${provider}`, { method: 'DELETE' });
  },

  async connectIntegration(provider: string): Promise<{ redirectUrl: string }> {
    return fetchWithAuth(`/api/integrations/${provider}/connect`);
  },

  async connectLinear(apiKey: string): Promise<void> {
    return fetchWithAuth('/api/integrations/linear/connect', {
      method: 'POST',
      body: JSON.stringify({ apiKey }),
    });
  },

  async getInvitations(): Promise<OrganizationInvitation[]> {
    return fetchWithAuth('/api/invitations');
  },

  async getOrganizationMembers(organizationId: string): Promise<OrganizationMember[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/members`);
  },

  async getOrganizationInvitations(organizationId: string): Promise<OrganizationInvitation[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/invitations`);
  },

  async createInvitation(organizationId: string, email: string, role: string = 'member', teamIds?: string[]): Promise<OrganizationInvitation> {
    return fetchWithAuth(`/api/organizations/${organizationId}/invitations`, {
      method: 'POST',
      body: JSON.stringify({ email, role, team_ids: teamIds }),
    });
  },

  async getInvitation(invitationId: string): Promise<{ id: string; email: string; role: string; organization_id: string; organization_name: string; expires_at: string }> {
    const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3001';
    const response = await fetch(`${API_BASE_URL}/api/organizations/invitations/${invitationId}`);
    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(error.error || `HTTP error! status: ${response.status}`);
    }
    return response.json();
  },

  async acceptInvitation(organizationId: string, invitationId: string): Promise<{ message: string; organization_id: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/invitations/${invitationId}/accept`, { method: 'POST' });
  },

  async cancelInvitation(organizationId: string, invitationId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/invitations/${invitationId}`, { method: 'DELETE' });
  },

  async resendInvitation(organizationId: string, invitationId: string): Promise<{ message: string; invitation: OrganizationInvitation }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/invitations/${invitationId}/resend`, { method: 'POST' });
  },

  async joinOrganization(organizationId: string, teamId?: string): Promise<{ message: string; organization_id: string }> {
    const url = teamId ? `/api/organizations/${organizationId}/join?team=${teamId}` : `/api/organizations/${organizationId}/join`;
    return fetchWithAuth(url, { method: 'POST' });
  },

  // Teams API
  _teamDataCache: new Map<string, TeamWithRole>(),
  _teamPrefetchCache: new Map<string, Promise<TeamWithRole>>(),

  async getTeams(organizationId: string): Promise<Team[]> {
    const teams = await fetchWithAuth(`/api/organizations/${organizationId}/teams`);
    teams.forEach((team: Team) => {
      const cacheKey = `${organizationId}:${team.id}`;
      this._teamDataCache.set(cacheKey, team as TeamWithRole);
    });
    return teams;
  },

  getCachedTeam(organizationId: string, teamId: string): TeamWithRole | null {
    const cacheKey = `${organizationId}:${teamId}`;
    return this._teamDataCache.get(cacheKey) || null;
  },

  async getTeam(organizationId: string, teamId: string, useCache = true): Promise<TeamWithRole> {
    const cacheKey = `${organizationId}:${teamId}`;
    if (useCache && this._teamPrefetchCache.has(cacheKey)) {
      const cachedPromise = this._teamPrefetchCache.get(cacheKey)!;
      this._teamPrefetchCache.delete(cacheKey);
      const team = await cachedPromise;
      this._teamDataCache.set(cacheKey, team);
      return team;
    }
    const team = await fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}`);
    this._teamDataCache.set(cacheKey, team);
    return team;
  },

  async prefetchTeam(organizationId: string, teamId: string): Promise<void> {
    const cacheKey = `${organizationId}:${teamId}`;
    if (!this._teamPrefetchCache.has(cacheKey)) {
      const promise = fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}`).then((team) => {
        this._teamDataCache.set(cacheKey, team);
        return team;
      }).catch(() => {
        this._teamPrefetchCache.delete(cacheKey);
        throw new Error('Failed to prefetch team');
      });
      this._teamPrefetchCache.set(cacheKey, promise);
    }
  },

  async createTeam(organizationId: string, name: string, description?: string): Promise<TeamWithRole> {
    const team = await fetchWithAuth(`/api/organizations/${organizationId}/teams`, {
      method: 'POST',
      body: JSON.stringify({ name, description }),
    });
    const cacheKey = `${organizationId}:${team.id}`;
    this._teamDataCache.set(cacheKey, team);
    return team;
  },

  async updateTeam(organizationId: string, teamId: string, data: { name?: string; avatar_url?: string; description?: string }): Promise<Team> {
    const team = await fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
    const cacheKey = `${organizationId}:${teamId}`;
    const cached = this._teamDataCache.get(cacheKey);
    if (cached) {
      this._teamDataCache.set(cacheKey, { ...cached, ...team });
    }
    return team;
  },

  async deleteTeam(organizationId: string, teamId: string): Promise<{ message: string }> {
    const result = await fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}`, { method: 'DELETE' });
    const cacheKey = `${organizationId}:${teamId}`;
    this._teamDataCache.delete(cacheKey);
    return result;
  },

  async getTeamMembers(organizationId: string, teamId: string): Promise<TeamMember[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/members`);
  },

  async addTeamMember(organizationId: string, teamId: string, userId: string, roleId?: string): Promise<{ id: string; team_id: string; user_id: string; role_id?: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/members`, {
      method: 'POST',
      body: JSON.stringify({ user_id: userId, role_id: roleId }),
    });
  },

  async updateTeamMemberRole(organizationId: string, teamId: string, userId: string, roleId: string): Promise<{ id: string; team_id: string; user_id: string; role_id: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/members/${userId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role_id: roleId }),
    });
  },

  async removeTeamMember(organizationId: string, teamId: string, memberId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/members/${memberId}`, { method: 'DELETE' });
  },

  async getTeamRoles(organizationId: string, teamId: string): Promise<TeamRole[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/roles`);
  },

  async createTeamRole(organizationId: string, teamId: string, data: { name: string; display_name?: string; permissions?: TeamPermissions; color?: string | null }): Promise<TeamRole> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/roles`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateTeamRole(organizationId: string, teamId: string, roleId: string, data: { name?: string; display_name?: string; display_order?: number; permissions?: TeamPermissions; color?: string | null }): Promise<TeamRole> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/roles/${roleId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async deleteTeamRole(organizationId: string, teamId: string, roleId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/roles/${roleId}`, { method: 'DELETE' });
  },

  async transferTeamOwnership(organizationId: string, teamId: string, userId: string, newRole: string = 'member'): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/transfer-ownership`, {
      method: 'POST',
      body: JSON.stringify({ user_id: userId, new_role: newRole }),
    });
  },

  // Team Notifications / Integrations API
  async getTeamConnections(organizationId: string, teamId: string): Promise<{ inherited: CiCdConnection[]; team: CiCdConnection[] }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/connections`);
  },

  async deleteTeamConnection(organizationId: string, teamId: string, connectionId: string): Promise<{ success: boolean }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/connections/${connectionId}`, { method: 'DELETE' });
  },

  async createTeamEmailNotification(organizationId: string, teamId: string, email: string): Promise<{ success: boolean; id: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/email-notifications`, {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  async createTeamCustomIntegration(
    organizationId: string,
    teamId: string,
    data: { name: string; type: 'notification' | 'ticketing'; webhook_url: string; icon_url?: string }
  ): Promise<{ success: boolean; id: string; secret: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/custom-integrations`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getTeamNotificationRules(organizationId: string, teamId: string): Promise<OrganizationNotificationRule[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/notification-rules`);
  },

  async createTeamNotificationRule(
    organizationId: string,
    teamId: string,
    data: { name: string; triggerType: string; minDepscoreThreshold?: number; customCode?: string; destinations: any[]; createdByName?: string }
  ): Promise<OrganizationNotificationRule> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/notification-rules`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateTeamNotificationRule(
    organizationId: string,
    teamId: string,
    ruleId: string,
    data: Partial<{ name: string; triggerType: string; minDepscoreThreshold?: number; customCode?: string; destinations: any[] }>
  ): Promise<OrganizationNotificationRule> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/notification-rules/${ruleId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async deleteTeamNotificationRule(organizationId: string, teamId: string, ruleId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/teams/${teamId}/notification-rules/${ruleId}`, { method: 'DELETE' });
  },

  // Projects API
  _projectDataCache: new Map<string, ProjectWithRole>(),

  async getProjects(organizationId: string): Promise<Project[]> {
    const projects = await fetchWithAuth(`/api/organizations/${organizationId}/projects`);
    projects.forEach((project: Project) => {
      const cacheKey = `${organizationId}:${project.id}`;
      this._projectDataCache.set(cacheKey, project as ProjectWithRole);
    });
    return projects;
  },

  getCachedProject(organizationId: string, projectId: string): ProjectWithRole | null {
    const cacheKey = `${organizationId}:${projectId}`;
    return this._projectDataCache.get(cacheKey) || null;
  },

  async createProject(organizationId: string, data: { name: string; team_ids?: string[]; asset_tier?: AssetTier }): Promise<Project> {
    const project = await fetchWithAuth(`/api/organizations/${organizationId}/projects`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
    const cacheKey = `${organizationId}:${project.id}`;
    this._projectDataCache.set(cacheKey, project as ProjectWithRole);
    return project;
  },

  async updateProject(organizationId: string, projectId: string, data: { name?: string; team_ids?: string[]; auto_bump?: boolean; asset_tier?: AssetTier }): Promise<Project> {
    const project = await fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
    const cacheKey = `${organizationId}:${projectId}`;
    const cached = this._projectDataCache.get(cacheKey);
    if (cached) {
      this._projectDataCache.set(cacheKey, { ...cached, ...project });
    }
    return project;
  },

  async deleteProject(organizationId: string, projectId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}`, { method: 'DELETE' });
  },

  async updateMemberRole(organizationId: string, userId: string, role: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/members/${userId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role }),
    });
  },

  async removeMember(organizationId: string, userId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/members/${userId}`, { method: 'DELETE' });
  },

  async updateOrganization(organizationId: string, data: { name?: string; avatar_url?: string }): Promise<Organization> {
    return fetchWithAuth(`/api/organizations/${organizationId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async deleteOrganization(organizationId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}`, { method: 'DELETE' });
  },

  async dismissGetStarted(organizationId: string): Promise<void> {
    await fetchWithAuth(`/api/organizations/${organizationId}/dismiss-get-started`, { method: 'POST' });
  },

  async getOrganizationIntegrations(organizationId: string): Promise<OrganizationIntegration[]> {
    return fetchWithAuth(`/api/integrations/organizations/${organizationId}/integrations`);
  },

  async getOrganizationConnections(organizationId: string): Promise<CiCdConnection[]> {
    return fetchWithAuth(`/api/integrations/organizations/${organizationId}/connections`);
  },

  async deleteOrganizationConnection(organizationId: string, connectionId: string): Promise<{ success: boolean; provider: string; installationId?: string; revokeUrl?: string }> {
    return fetchWithAuth(`/api/integrations/organizations/${organizationId}/connections/${connectionId}`, { method: 'DELETE' });
  },

  async connectSlackOrg(organizationId: string, projectId?: string, teamId?: string): Promise<{ redirectUrl: string }> {
    const params = new URLSearchParams({ org_id: organizationId });
    if (projectId) params.set('project_id', projectId);
    if (teamId) params.set('team_id', teamId);
    return fetchWithAuth(`/api/integrations/slack/install?${params}`);
  },

  async connectDiscordOrg(organizationId: string, projectId?: string, teamId?: string): Promise<{ redirectUrl: string }> {
    const params = new URLSearchParams({ org_id: organizationId });
    if (projectId) params.set('project_id', projectId);
    if (teamId) params.set('team_id', teamId);
    return fetchWithAuth(`/api/integrations/discord/install?${params}`);
  },

  async connectJiraOrg(organizationId: string, projectId?: string, teamId?: string): Promise<{ redirectUrl: string }> {
    const params = new URLSearchParams({ org_id: organizationId });
    if (projectId) params.set('project_id', projectId);
    if (teamId) params.set('team_id', teamId);
    return fetchWithAuth(`/api/integrations/jira/install?${params}`);
  },

  async connectJiraPatOrg(organizationId: string, baseUrl: string, token: string, projectId?: string, teamId?: string): Promise<{ success: boolean }> {
    return fetchWithAuth(`/api/integrations/jira/connect-pat`, {
      method: 'POST',
      body: JSON.stringify({
        org_id: organizationId,
        base_url: baseUrl,
        token,
        ...(projectId ? { project_id: projectId } : {}),
        ...(teamId ? { team_id: teamId } : {}),
      }),
    });
  },

  async getProjectConnections(organizationId: string, projectId: string): Promise<{ inherited: CiCdConnection[]; team: CiCdConnection[]; project: CiCdConnection[] }> {
    const result = await fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/connections`);
    return { inherited: result.inherited || [], team: result.team || [], project: result.project || [] };
  },

  async deleteProjectConnection(organizationId: string, projectId: string, connectionId: string): Promise<{ success: boolean }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/connections/${connectionId}`, { method: 'DELETE' });
  },

  async getProjectNotificationRules(organizationId: string, projectId: string): Promise<OrganizationNotificationRule[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/notification-rules`);
  },

  async createProjectNotificationRule(
    organizationId: string,
    projectId: string,
    data: {
      name: string;
      triggerType: 'weekly_digest' | 'vulnerability_discovered' | 'custom_code_pipeline';
      minDepscoreThreshold?: number;
      customCode?: string;
      destinations: Array<{ integrationType: string; targetId: string }>;
      createdByName?: string;
    }
  ): Promise<OrganizationNotificationRule> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/notification-rules`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateProjectNotificationRule(
    organizationId: string,
    projectId: string,
    ruleId: string,
    data: {
      name?: string;
      triggerType?: 'weekly_digest' | 'vulnerability_discovered' | 'custom_code_pipeline';
      minDepscoreThreshold?: number;
      customCode?: string;
      destinations?: Array<{ integrationType: string; targetId: string }>;
    }
  ): Promise<OrganizationNotificationRule> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/notification-rules/${ruleId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async deleteProjectNotificationRule(organizationId: string, projectId: string, ruleId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/notification-rules/${ruleId}`, {
      method: 'DELETE',
    });
  },

  async createProjectEmailNotification(organizationId: string, projectId: string, email: string): Promise<{ success: boolean; id: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/email-notifications`, {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  async createProjectCustomIntegration(
    organizationId: string,
    projectId: string,
    data: { name: string; type: 'notification' | 'ticketing'; webhook_url: string; icon_url?: string }
  ): Promise<{ success: boolean; id: string; secret: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/custom-integrations`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async connectLinearOrg(organizationId: string, projectId?: string, teamId?: string): Promise<{ redirectUrl: string }> {
    const params = new URLSearchParams({ org_id: organizationId });
    if (projectId) params.set('project_id', projectId);
    if (teamId) params.set('team_id', teamId);
    return fetchWithAuth(`/api/integrations/linear/install?${params}`);
  },

  async connectAsanaOrg(organizationId: string, projectId?: string): Promise<{ redirectUrl: string }> {
    const params = new URLSearchParams({ org_id: organizationId });
    if (projectId) params.set('project_id', projectId);
    return fetchWithAuth(`/api/integrations/asana/install?${params}`);
  },

  async createEmailNotification(organizationId: string, email: string): Promise<{ success: boolean; id: string }> {
    return fetchWithAuth(`/api/integrations/organizations/${organizationId}/email-notifications`, {
      method: 'POST',
      body: JSON.stringify({ email }),
    });
  },

  async createCustomIntegration(organizationId: string, data: { name: string; type: 'notification' | 'ticketing'; webhook_url: string; icon_url?: string }): Promise<{ success: boolean; id: string; secret: string }> {
    return fetchWithAuth(`/api/integrations/organizations/${organizationId}/custom-integrations`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateCustomIntegration(organizationId: string, integrationId: string, data: { name?: string; webhook_url?: string; icon_url?: string; regenerate_secret?: boolean }): Promise<{ success: boolean; secret?: string }> {
    return fetchWithAuth(`/api/integrations/organizations/${organizationId}/custom-integrations/${integrationId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async testCustomIntegration(organizationId: string, integrationId: string): Promise<{ success: boolean; status: number; statusText: string; message: string }> {
    return fetchWithAuth(`/api/integrations/organizations/${organizationId}/custom-integrations/${integrationId}/test`, {
      method: 'POST',
    });
  },

  async uploadIntegrationIcon(organizationId: string, file: File): Promise<{ url: string }> {
    const token = await getAuthToken();
    if (!token) throw new Error('Not authenticated');
    const response = await fetch(`${API_BASE_URL}/api/integrations/organizations/${organizationId}/custom-integrations/upload-icon`, {
      method: 'POST',
      headers: {
        'Content-Type': file.type,
        'Authorization': `Bearer ${token}`,
      },
      body: file,
    });
    if (!response.ok) {
      const err = await response.json().catch(() => ({ error: 'Upload failed' }));
      throw new Error(err.error || 'Upload failed');
    }
    return response.json();
  },

  async transferOrganizationOwnership(organizationId: string, userId: string, newRole: string = 'admin'): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/transfer-ownership`, {
      method: 'POST',
      body: JSON.stringify({ user_id: userId, new_role: newRole }),
    });
  },

  async getOrganizationRoles(organizationId: string): Promise<OrganizationRole[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/roles`);
  },

  async createOrganizationRole(organizationId: string, data: { name: string; display_name?: string; display_order?: number; permissions?: RolePermissions; color?: string | null }): Promise<OrganizationRole> {
    return fetchWithAuth(`/api/organizations/${organizationId}/roles`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateOrganizationRole(organizationId: string, roleId: string, data: { name?: string; display_name?: string; display_order?: number; permissions?: RolePermissions; color?: string | null }): Promise<OrganizationRole> {
    return fetchWithAuth(`/api/organizations/${organizationId}/roles/${roleId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async deleteOrganizationRole(organizationId: string, roleId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/roles/${roleId}`, { method: 'DELETE' });
  },

  async getUserProfile(): Promise<{ user_id: string; avatar_url: string | null; full_name: string | null }> {
    return fetchWithAuth('/api/user-profile');
  },

  async updateUserProfile(data: { avatar_url?: string; full_name?: string }): Promise<{ user_id: string; avatar_url: string | null; full_name: string | null }> {
    return fetchWithAuth('/api/user-profile', {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async getOrganizationNotificationRules(organizationId: string): Promise<OrganizationNotificationRule[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/notification-rules`);
  },

  async createOrganizationNotificationRule(
    organizationId: string,
    data: {
      name: string;
      triggerType: 'weekly_digest' | 'vulnerability_discovered' | 'custom_code_pipeline';
      minDepscoreThreshold?: number;
      customCode?: string;
      destinations: Array<{ integrationType: string; targetId: string }>;
      createdByName?: string;
    }
  ): Promise<OrganizationNotificationRule> {
    return fetchWithAuth(`/api/organizations/${organizationId}/notification-rules`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async updateOrganizationNotificationRule(
    organizationId: string,
    ruleId: string,
    data: {
      name?: string;
      triggerType?: 'weekly_digest' | 'vulnerability_discovered' | 'custom_code_pipeline';
      minDepscoreThreshold?: number;
      customCode?: string;
      destinations?: Array<{ integrationType: string; targetId: string }>;
    }
  ): Promise<OrganizationNotificationRule> {
    return fetchWithAuth(`/api/organizations/${organizationId}/notification-rules/${ruleId}`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  async deleteOrganizationNotificationRule(organizationId: string, ruleId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/notification-rules/${ruleId}`, {
      method: 'DELETE',
    });
  },

  async getOrganizationPolicies(organizationId: string): Promise<OrganizationPolicies> {
    return fetchWithAuth(`/api/organizations/${organizationId}/policies`);
  },

  async updateOrganizationPolicies(organizationId: string, policies: { policy_code: string }): Promise<OrganizationPolicies> {
    return fetchWithAuth(`/api/organizations/${organizationId}/policies`, {
      method: 'PUT',
      body: JSON.stringify({ policy_code: policies.policy_code }),
    });
  },

  async recommendOrganizationLicenses(organizationId: string, description: string): Promise<{ recommended_licenses: string[] }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/policies/recommend`, {
      method: 'POST',
      body: JSON.stringify({ description }),
    });
  },

  async policyAIAssistStream(
    organizationId: string,
    params: {
      message: string;
      targetEditor: 'compliance' | 'pullRequest';
      currentComplianceCode: string;
      currentPullRequestCode: string;
      conversationHistory: Array<{ role: 'user' | 'assistant'; content: string }>;
    },
  ): Promise<Response> {
    const token = await getAuthToken();
    if (!token) throw new Error('Not authenticated');

    const response = await fetch(`${API_BASE_URL}/api/organizations/${organizationId}/policies/ai-assist`, {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'Content-Type': 'application/json',
        'Accept': 'text/event-stream',
      },
      body: JSON.stringify(params),
    });

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(error.error || `HTTP error! status: ${response.status}`);
    }

    return response;
  },

  async notificationRuleAIAssistStream(
    organizationId: string,
    params: {
      message: string;
      currentCode: string;
      conversationHistory: Array<{ role: 'user' | 'assistant'; content: string }>;
    },
  ): Promise<Response> {
    const token = await getAuthToken();
    if (!token) throw new Error('Not authenticated');

    const response = await fetch(
      `${API_BASE_URL}/api/organizations/${organizationId}/notifications/ai-assist`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${token}`,
          'Content-Type': 'application/json',
          Accept: 'text/event-stream',
        },
        body: JSON.stringify(params),
      },
    );

    if (!response.ok) {
      const error = await response.json().catch(() => ({ error: 'Unknown error' }));
      throw new Error(error.error || `HTTP error! status: ${response.status}`);
    }

    return response;
  },

  async getActivities(
    organizationId: string,
    filters?: {
      start_date?: string;
      end_date?: string;
      activity_type?: string | string[];
      team_id?: string;
      project_id?: string;
      limit?: number;
      offset?: number;
    }
  ): Promise<Activity[]> {
    const params = new URLSearchParams();
    if (filters?.start_date) params.append('start_date', filters.start_date);
    if (filters?.end_date) params.append('end_date', filters.end_date);
    if (filters?.activity_type) {
      const types = Array.isArray(filters.activity_type) ? filters.activity_type : [filters.activity_type];
      types.forEach(type => params.append('activity_type', type));
    }
    if (filters?.team_id) params.append('team_id', filters.team_id);
    if (filters?.project_id) params.append('project_id', filters.project_id);
    if (filters?.limit) params.append('limit', filters.limit.toString());
    if (filters?.offset) params.append('offset', filters.offset.toString());

    const queryString = params.toString();
    const url = `/api/organizations/${organizationId}/activities${queryString ? `?${queryString}` : ''}`;
    return fetchWithAuth(url);
  },

  async getAegisStatus(organizationId: string): Promise<{ enabled: boolean }> {
    return fetchWithAuth(`/api/aegis/status/${organizationId}`);
  },

  async enableAegis(organizationId: string): Promise<{ enabled: boolean }> {
    return fetchWithAuth(`/api/aegis/enable/${organizationId}`, { method: 'POST' });
  },

  async sendAegisMessage(organizationId: string, threadId: string | null, message: string): Promise<AegisMessageResponse> {
    return fetchWithAuth('/api/aegis/handle', {
      method: 'POST',
      body: JSON.stringify({ organizationId, threadId, message }),
    });
  },

  async getAegisThreads(organizationId: string): Promise<AegisThread[]> {
    return fetchWithAuth(`/api/aegis/threads/${organizationId}`);
  },

  async getAegisThreadMessages(threadId: string): Promise<AegisMessage[]> {
    return fetchWithAuth(`/api/aegis/threads/${threadId}/messages`);
  },

  async createAegisThread(organizationId: string, title?: string): Promise<AegisThread> {
    return fetchWithAuth('/api/aegis/threads', {
      method: 'POST',
      body: JSON.stringify({ organizationId, title }),
    });
  },

  async getAegisActivity(organizationId: string, filters?: { start_date?: string; end_date?: string; limit?: number; offset?: number }): Promise<AegisActivityLog[]> {
    const params = new URLSearchParams();
    if (filters?.start_date) params.append('start_date', filters.start_date);
    if (filters?.end_date) params.append('end_date', filters.end_date);
    if (filters?.limit) params.append('limit', filters.limit.toString());
    if (filters?.offset) params.append('offset', filters.offset.toString());

    const queryString = params.toString();
    const url = `/api/aegis/activity/${organizationId}${queryString ? `?${queryString}` : ''}`;
    return fetchWithAuth(url);
  },

  async getAegisAutomations(organizationId: string): Promise<AegisAutomation[]> {
    return fetchWithAuth(`/api/aegis/automations/${organizationId}`);
  },

  async createAegisAutomation(organizationId: string, automation: { name: string; description?: string; schedule: string }): Promise<AegisAutomation> {
    return fetchWithAuth('/api/aegis/automations', {
      method: 'POST',
      body: JSON.stringify({ organizationId, ...automation }),
    });
  },

  async updateAegisAutomation(organizationId: string, automationId: string, updates: { name?: string; description?: string; schedule?: string; enabled?: boolean }): Promise<AegisAutomation> {
    return fetchWithAuth(`/api/aegis/automations/${automationId}`, {
      method: 'PUT',
      body: JSON.stringify(updates),
    });
  },

  async deleteAegisAutomation(organizationId: string, automationId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/aegis/automations/${automationId}`, { method: 'DELETE' });
  },

  async runAegisAutomation(organizationId: string, automationId: string): Promise<{ message: string; job: any }> {
    return fetchWithAuth(`/api/aegis/automations/${automationId}/run`, { method: 'POST' });
  },

  async getAegisInbox(organizationId: string): Promise<AegisInboxMessage[]> {
    return fetchWithAuth(`/api/aegis/inbox/${organizationId}`);
  },

  async markInboxRead(organizationId: string, messageId: string): Promise<AegisInboxMessage> {
    return fetchWithAuth(`/api/aegis/inbox/${messageId}/read`, { method: 'PUT' });
  },

  _projectPrefetchCache: new Map<string, Promise<ProjectWithRole>>(),

  async getProject(organizationId: string, projectId: string, useCache = true): Promise<ProjectWithRole> {
    const cacheKey = `${organizationId}:${projectId}`;
    if (useCache && this._projectPrefetchCache.has(cacheKey)) {
      const cachedPromise = this._projectPrefetchCache.get(cacheKey)!;
      this._projectPrefetchCache.delete(cacheKey);
      const project = await cachedPromise;
      this._projectDataCache.set(cacheKey, project);
      return project;
    }

    const project = await fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}`);
    this._projectDataCache.set(cacheKey, project);
    return project;
  },

  async prefetchProject(organizationId: string, projectId: string): Promise<void> {
    const cacheKey = `${organizationId}:${projectId}`;
    if (!this._projectPrefetchCache.has(cacheKey)) {
      const promise = fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}`).then((project) => {
        this._projectDataCache.set(cacheKey, project);
        return project;
      }).catch(() => {
        this._projectPrefetchCache.delete(cacheKey);
        throw new Error('Failed to prefetch project');
      });
      this._projectPrefetchCache.set(cacheKey, promise);
    }
  },

  async getProjectRoles(organizationId: string, projectId: string): Promise<ProjectRole[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/roles`);
  },

  async getProjectMembers(organizationId: string, projectId: string): Promise<ProjectMembersResponse> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/members`);
  },

  async addProjectMember(organizationId: string, projectId: string, userId: string, roleId?: string): Promise<ProjectMember> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/members`, {
      method: 'POST',
      body: JSON.stringify({ user_id: userId, role_id: roleId }),
    });
  },

  async updateProjectMemberRole(organizationId: string, projectId: string, userId: string, roleId: string): Promise<ProjectMember> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/members/${userId}/role`, {
      method: 'PUT',
      body: JSON.stringify({ role_id: roleId }),
    });
  },

  async removeProjectMember(organizationId: string, projectId: string, userId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/members/${userId}`, { method: 'DELETE' });
  },

  // Project Teams (Owner and Contributing)
  async getProjectTeams(organizationId: string, projectId: string): Promise<ProjectTeamsResponse> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/teams`);
  },

  _projectRepositoriesCache: new Map<
    string,
    { connectedRepository: ProjectRepository | null; repositories: Array<{ id: number; full_name: string; default_branch: string; private: boolean; framework: string }>; fetchedAt: number }
  >(),

  getCachedProjectRepositories(
    organizationId: string,
    projectId: string
  ): { connectedRepository: ProjectRepository | null; repositories: Array<{ id: number; full_name: string; default_branch: string; private: boolean; framework: string }> } | null {
    const key = `${organizationId}:${projectId}`;
    const entry = this._projectRepositoriesCache.get(key);
    if (!entry) return null;
    return { connectedRepository: entry.connectedRepository, repositories: entry.repositories };
  },

  setProjectRepositoriesCache(
    organizationId: string,
    projectId: string,
    data: { connectedRepository: ProjectRepository | null; repositories: Array<{ id: number; full_name: string; default_branch: string; private: boolean; framework: string }> }
  ): void {
    this._projectRepositoriesCache.set(`${organizationId}:${projectId}`, { ...data, fetchedAt: Date.now() });
  },

  invalidateProjectRepositoriesCache(organizationId: string, projectId: string): void {
    this._projectRepositoriesCache.delete(`${organizationId}:${projectId}`);
  },

  _organizationRepositoriesCache: new Map<
    string,
    { repositories: RepoWithProvider[]; fetchedAt: number }
  >(),

  async getOrganizationRepositories(
    organizationId: string,
    integrationId?: string
  ): Promise<{
    repositories: RepoWithProvider[];
  }> {
    const cacheKey = `${organizationId}:${integrationId || 'all'}`;
    const cached = this._organizationRepositoriesCache.get(cacheKey);
    if (cached && Date.now() - cached.fetchedAt < REPOS_CACHE_TTL_MS) {
      return { repositories: cached.repositories };
    }
    const params = integrationId ? `?integration_id=${integrationId}` : '';
    const result = await fetchWithAuth(`/api/organizations/${organizationId}/repositories${params}`);
    this._organizationRepositoriesCache.set(cacheKey, { repositories: result.repositories, fetchedAt: Date.now() });
    return result;
  },

  _organizationRepositoryScanCache: new Map<
    string,
    {
      data: {
        isMonorepo: boolean;
        confidence?: 'high' | 'medium';
        potentialProjects: Array<{
          name: string;
          path: string;
          isLinked: boolean;
          linkedByProjectId?: string;
          linkedByProjectName?: string;
        }>;
      };
      fetchedAt: number;
    }
  >(),

  async getOrganizationRepositoryScan(
    organizationId: string,
    repoFullName: string,
    defaultBranch: string,
    integrationId: string
  ): Promise<{
    isMonorepo: boolean;
    confidence?: 'high' | 'medium';
    potentialProjects: Array<{
      name: string;
      path: string;
      ecosystem?: string;
      isLinked: boolean;
      linkedByProjectId?: string;
      linkedByProjectName?: string;
    }>;
  }> {
    const key = `${organizationId}:${repoFullName}:${defaultBranch}:${integrationId}`;
    const cached = this._organizationRepositoryScanCache.get(key);
    if (cached && Date.now() - cached.fetchedAt < SCAN_CACHE_TTL_MS) {
      return cached.data;
    }
    const params = new URLSearchParams({ repo_full_name: repoFullName, default_branch: defaultBranch, integration_id: integrationId });
    const data = await fetchWithAuth(`/api/organizations/${organizationId}/repositories/scan?${params}`);
    this._organizationRepositoryScanCache.set(key, { data, fetchedAt: Date.now() });
    return data;
  },

  async getProjectRepositories(
    organizationId: string,
    projectId: string,
    integrationId?: string
  ): Promise<{
    connectedRepository: (ProjectRepository & { provider?: string }) | null;
    repositories: RepoWithProvider[];
  }> {
    const key = `${organizationId}:${projectId}:${integrationId || 'all'}`;
    const cached = this._projectRepositoriesCache.get(key);
    if (cached && Date.now() - cached.fetchedAt < REPOS_CACHE_TTL_MS) {
      return { connectedRepository: cached.connectedRepository, repositories: cached.repositories };
    }
    const params = integrationId ? `?integration_id=${integrationId}` : '';
    const data = await fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/repositories${params}`);
    this.setProjectRepositoriesCache(organizationId, projectId, data);
    return data;
  },

  async getRepositoryScan(
    organizationId: string,
    projectId: string,
    repoFullName: string,
    defaultBranch: string,
    integrationId: string
  ): Promise<{
    isMonorepo: boolean;
    confidence?: 'high' | 'medium';
    potentialProjects: Array<{
      name: string;
      path: string;
      ecosystem?: string;
      isLinked: boolean;
      linkedByProjectId?: string;
      linkedByProjectName?: string;
    }>;
  }> {
    const params = new URLSearchParams({ repo_full_name: repoFullName, default_branch: defaultBranch, integration_id: integrationId });
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/repositories/scan?${params}`
    );
  },

  async connectProjectRepository(
    organizationId: string,
    projectId: string,
    data: {
      repo_id: number;
      repo_full_name: string;
      default_branch: string;
      framework?: string;
      package_json_path?: string;
      ecosystem?: string;
      provider?: string;
      integration_id?: string;
    }
  ): Promise<ProjectRepository> {
    const result = await fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/repositories/connect`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
    const scanKey = `${organizationId}:${data.repo_full_name}:${data.default_branch}`;
    this._organizationRepositoryScanCache.delete(scanKey);
    return result;
  },

  async updateProjectRepositorySettings(
    organizationId: string,
    projectId: string,
    data: { pull_request_comments_enabled?: boolean }
  ): Promise<ProjectRepository> {
    const result = await fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/repositories/settings`,
      { method: 'PATCH', body: JSON.stringify(data) }
    );
    this.invalidateProjectRepositoriesCache(organizationId, projectId);
    return result;
  },

  // Dependency caching methods
  getCachedDependency(projectId: string, dependencyId: string): ProjectDependency | null {
    const cacheKey = `${projectId}:${dependencyId}`;
    return this._dependencyDataCache.get(cacheKey) || null;
  },

  cacheDependency(projectId: string, dependency: ProjectDependency): void {
    const cacheKey = `${projectId}:${dependency.id}`;
    this._dependencyDataCache.set(cacheKey, dependency);
  },

  async getProjectDependencies(
    organizationId: string,
    projectId: string,
    options?: { bypassCache?: boolean; cachedOnly?: boolean }
  ): Promise<ProjectDependency[]> {
    let url = `/api/organizations/${organizationId}/projects/${projectId}/dependencies`;
    if (options?.cachedOnly) {
      url += '?cached_only=true';
    } else if (options?.bypassCache) {
      url += `?refresh=true&_t=${Date.now()}`;
    }
    const fetchOptions: RequestInit = options?.bypassCache ? { cache: 'no-store' } : {};
    const deps = await fetchWithAuth(url, fetchOptions);
    // Cache all dependencies for instant display when navigating to dependency pages
    deps.forEach((dep: ProjectDependency) => {
      this.cacheDependency(projectId, dep);
    });
    return deps;
  },

  async getDependencyOverview(
    organizationId: string,
    projectId: string,
    projectDependencyId: string,
    options?: { bypassCache?: boolean }
  ): Promise<{
    name: string | null;
    version: string | null;
    score: number | null;
    critical_vulns: number;
    high_vulns: number;
    medium_vulns: number;
    low_vulns: number;
    github_url: string | null;
    license: string | null;
    weekly_downloads: number | null;
    latest_release_date: string | null;
    latest_version: string | null;
    last_published_at: string | null;
    releases_last_12_months: number | null;
    openssf_score: number | null;
    openssf_penalty: number | null;
    popularity_penalty: number | null;
    maintenance_penalty: number | null;
    dependency_id: string;
    dependency_version_id: string;
    files_importing_count: number;
    imported_functions: string[];
    imported_file_paths?: string[];
    ai_usage_summary: string | null;
    ai_usage_analyzed_at: string | null;
    other_projects_using_count: number;
    other_projects_using_names: string[];
    description: string | null;
    deprecation: { recommended_alternative: string; deprecated_by: string | null; created_at: string; scope?: 'organization' | 'team'; team_id?: string } | null;
    remove_pr_url: string | null;
    remove_pr_number: number | null;
  }> {
    let url = `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${projectDependencyId}/overview`;
    if (options?.bypassCache) {
      url += `?_t=${Date.now()}`;
    }
    const fetchOptions: RequestInit = options?.bypassCache ? { cache: 'no-store' } : {};
    return fetchWithAuth(url, fetchOptions);
  },

  async analyzeDependencyUsage(
    organizationId: string,
    projectId: string,
    projectDependencyId: string
  ): Promise<{ ai_usage_summary: string; ai_usage_analyzed_at: string }> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${projectDependencyId}/analyze-usage`,
      { method: 'POST' }
    );
  },

  async getDependencyVersions(
    organizationId: string,
    projectId: string,
    projectDependencyId: string,
    options?: { limit: number; offset: number }
  ): Promise<DependencyVersionsResponse> {
    const url = `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${projectDependencyId}/versions`;
    const params = options ? `?limit=${options.limit}&offset=${options.offset}` : '';
    return fetchWithAuth(url + params);
  },

  async getDependencySupplyChain(
    organizationId: string,
    projectId: string,
    projectDependencyId: string
  ): Promise<SupplyChainResponse> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${projectDependencyId}/supply-chain`
    );
  },

  async getBatchSupplyChains(
    organizationId: string,
    projectId: string,
    projectDependencyIds: string[]
  ): Promise<Record<string, { children: SupplyChainChild[] }>> {
    if (projectDependencyIds.length === 0) return {};
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/supply-chains/batch`,
      {
        method: 'POST',
        body: JSON.stringify({ project_dependency_ids: projectDependencyIds }),
      }
    );
  },

  async getSupplyChainForVersion(
    organizationId: string,
    projectId: string,
    projectDependencyId: string,
    dependencyVersionId: string
  ): Promise<SupplyChainVersionResponse> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${projectDependencyId}/supply-chain/version/${dependencyVersionId}`
    );
  },

  async getProjectDependencySuggestionsBatch(
    organizationId: string,
    projectId: string,
    projectDependencyIds: string[]
  ): Promise<Record<string, { action: 'current' | 'bump'; safeVersion?: string; bumpPrUrl?: string; bumpPrNumber?: number }>> {
    if (projectDependencyIds.length === 0) return {};
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/suggestions-batch`,
      {
        method: 'POST',
        body: JSON.stringify({ project_dependency_ids: projectDependencyIds }),
      }
    );
  },

  async getLatestSafeVersion(
    organizationId: string,
    projectId: string,
    projectDependencyId: string,
    severity?: string,
    excludeBanned?: boolean,
    options?: { refresh?: boolean }
  ): Promise<LatestSafeVersionResponse> {
    const searchParams = new URLSearchParams();
    if (severity) searchParams.set('severity', severity);
    if (excludeBanned) searchParams.set('exclude_banned', 'true');
    if (options?.refresh) searchParams.set('refresh', 'true');
    const qs = searchParams.toString();
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${projectDependencyId}/supply-chain/latest-safe-version${qs ? `?${qs}` : ''}`
    );
  },

  async getBatchLatestSafeVersions(
    organizationId: string,
    projectId: string,
    projectDependencyIds: string[],
    options?: { severity?: string; excludeBanned?: boolean }
  ): Promise<Record<string, LatestSafeVersionResponse>> {
    if (projectDependencyIds.length === 0) return {};
    const searchParams = new URLSearchParams();
    searchParams.set('project_dependency_ids', projectDependencyIds.join(','));
    if (options?.severity) searchParams.set('severity', options.severity);
    if (options?.excludeBanned !== false) searchParams.set('exclude_banned', 'true');
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/supply-chains/latest-safe-versions?${searchParams.toString()}`
    );
  },

  // --- Dependency tab prefetching ---

  prefetchDependencyOverview(orgId: string, projectId: string, depId: string): void {
    const key = `${orgId}:${projectId}:${depId}`;
    if (!this._depOverviewPrefetchCache.has(key)) {
      const promise = Promise.all([
        this.getDependencyOverview(orgId, projectId, depId),
        this.getProjectPolicies(orgId, projectId).catch(() => null),
      ]).catch(() => {
        this._depOverviewPrefetchCache.delete(key);
        return [null, null] as [null, null];
      });
      this._depOverviewPrefetchCache.set(key, promise);
    }
  },

  consumePrefetchedOverview(orgId: string, projectId: string, depId: string): Promise<[any, ProjectEffectivePolicies | null]> | null {
    const key = `${orgId}:${projectId}:${depId}`;
    const cached = this._depOverviewPrefetchCache.get(key);
    if (cached) {
      this._depOverviewPrefetchCache.delete(key);
      return cached;
    }
    return null;
  },

  clearDependencyOverviewPrefetch(orgId: string, projectId: string, depId: string): void {
    this._depOverviewPrefetchCache.delete(`${orgId}:${projectId}:${depId}`);
  },

  prefetchDependencySupplyChain(orgId: string, projectId: string, depId: string): void {
    const key = `${orgId}:${projectId}:${depId}`;
    if (!this._supplyChainPrefetchCache.has(key)) {
      const promise = Promise.all([
        this.getDependencySupplyChain(orgId, projectId, depId),
        this.getProjectPolicies(orgId, projectId).catch(() => null),
      ]).catch(() => {
        this._supplyChainPrefetchCache.delete(key);
        return [null, null] as unknown as [SupplyChainResponse, ProjectEffectivePolicies | null];
      });
      this._supplyChainPrefetchCache.set(key, promise);
    }
  },

  consumePrefetchedSupplyChain(orgId: string, projectId: string, depId: string): Promise<[SupplyChainResponse, ProjectEffectivePolicies | null]> | null {
    const key = `${orgId}:${projectId}:${depId}`;
    const cached = this._supplyChainPrefetchCache.get(key);
    if (cached) {
      this._supplyChainPrefetchCache.delete(key);
      return cached;
    }
    return null;
  },

  prefetchWatchtowerData(depName: string, depId: string, orgId: string): void {
    const key = `${orgId}:${depId}`;
    if (!this._watchtowerPrefetchCache.has(key)) {
      const promise = Promise.all([
        this.getWatchtowerSummary(depName, depId).catch(() => null),
        this.getWatchtowerCommits(depName, 50, 0, orgId, depId)
          .catch(() => ({ commits: [], total: 0, limit: 50, offset: 0 } as WatchtowerCommitsResponse)),
      ]).catch(() => {
        this._watchtowerPrefetchCache.delete(key);
        return [null, { commits: [], total: 0, limit: 50, offset: 0 }] as [null, WatchtowerCommitsResponse];
      });
      this._watchtowerPrefetchCache.set(key, promise);
    }
  },

  consumePrefetchedWatchtower(orgId: string, depId: string): Promise<[WatchtowerSummary | null, WatchtowerCommitsResponse]> | null {
    const key = `${orgId}:${depId}`;
    const cached = this._watchtowerPrefetchCache.get(key);
    if (cached) {
      this._watchtowerPrefetchCache.delete(key);
      return cached;
    }
    return null;
  },

  prefetchDependencyNotes(orgId: string, projectId: string, projectDependencyId: string): void {
    const key = `${orgId}:${projectId}:${projectDependencyId}`;
    if (!this._notesPrefetchCache.has(key)) {
      const promise = this.getDependencyNotes(orgId, projectId, projectDependencyId).catch(() => {
        this._notesPrefetchCache.delete(key);
        return { notes: [] };
      });
      this._notesPrefetchCache.set(key, promise);
    }
  },

  consumePrefetchedNotes(orgId: string, projectId: string, projectDependencyId: string): Promise<{ notes: DependencyNote[] }> | null {
    const key = `${orgId}:${projectId}:${projectDependencyId}`;
    const cached = this._notesPrefetchCache.get(key);
    if (cached) {
      this._notesPrefetchCache.delete(key);
      return cached;
    }
    return null;
  },

  async updateDependencyWatching(
    organizationId: string,
    projectId: string,
    dependencyId: string,
    isWatching: boolean
  ): Promise<{ id: string; is_watching: boolean }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/dependencies/${dependencyId}/watching`, {
      method: 'PATCH',
      body: JSON.stringify({ is_watching: isWatching }),
    });
  },

  async clearWatchtowerCommits(
    organizationId: string,
    projectId: string,
    dependencyId: string
  ): Promise<{ id: string; watchtower_cleared_at: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/dependencies/${dependencyId}/clear-commits`, {
      method: 'PATCH',
    });
  },

  async patchWatchlistQuarantine(
    organizationId: string,
    projectId: string,
    dependencyId: string,
    quarantine_next_release: boolean
  ): Promise<{ quarantine_next_release: boolean }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/dependencies/${dependencyId}/watchlist-quarantine`, {
      method: 'PATCH',
      body: JSON.stringify({ quarantine_next_release }),
    });
  },

  async getProjectImportStatus(
    organizationId: string,
    projectId: string
  ): Promise<ProjectImportStatus> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/import-status`);
  },

  async requeueAstParsing(organizationId: string, projectId: string): Promise<{ success: boolean; message?: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/requeue-ast`, {
      method: 'POST',
    });
  },

  async getProjectVulnerabilities(
    organizationId: string,
    projectId: string
  ): Promise<ProjectVulnerability[]> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/vulnerabilities`);
  },

  async addProjectContributingTeam(organizationId: string, projectId: string, teamId: string): Promise<ProjectContributingTeam> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/contributing-teams`, {
      method: 'POST',
      body: JSON.stringify({ team_id: teamId }),
    });
  },

  async removeProjectContributingTeam(organizationId: string, projectId: string, teamId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/contributing-teams/${teamId}`, { method: 'DELETE' });
  },

  async transferProjectOwnership(organizationId: string, projectId: string, newOwnerTeamId: string): Promise<{ message: string; owner_team: { id: string; name: string; description?: string | null; avatar_url?: string | null } }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/transfer-ownership`, {
      method: 'POST',
      body: JSON.stringify({ new_owner_team_id: newOwnerTeamId }),
    });
  },

  // Project policy exceptions
  async getProjectPolicies(organizationId: string, projectId: string): Promise<ProjectEffectivePolicies> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/policies`);
  },

  async createPolicyException(
    organizationId: string,
    projectId: string,
    data: {
      reason: string;
      requested_policy_code?: string;
      policy_type?: 'compliance' | 'pull_request' | 'full';
      additional_licenses?: string[];
      slsa_enforcement?: string | null;
      slsa_level?: number | null;
    }
  ): Promise<ProjectPolicyException> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/policy-exceptions`, {
      method: 'POST',
      body: JSON.stringify(data),
    });
  },

  async getOrganizationPolicyExceptions(organizationId: string, status?: string): Promise<ProjectPolicyException[]> {
    const url = status
      ? `/api/organizations/${organizationId}/policy-exceptions?status=${status}`
      : `/api/organizations/${organizationId}/policy-exceptions`;
    return fetchWithAuth(url);
  },

  async reviewPolicyException(organizationId: string, exceptionId: string, status: 'accepted' | 'rejected'): Promise<ProjectPolicyException> {
    return fetchWithAuth(`/api/organizations/${organizationId}/policy-exceptions/${exceptionId}`, {
      method: 'PUT',
      body: JSON.stringify({ status }),
    });
  },

  async revokePolicyException(organizationId: string, exceptionId: string): Promise<ProjectPolicyException> {
    return fetchWithAuth(`/api/organizations/${organizationId}/policy-exceptions/${exceptionId}/revoke`, {
      method: 'PUT',
    });
  },

  async deletePolicyException(organizationId: string, exceptionId: string): Promise<{ message: string }> {
    return fetchWithAuth(`/api/organizations/${organizationId}/policy-exceptions/${exceptionId}`, { method: 'DELETE' });
  },

  // Project PR Guardrails
  async getProjectPRGuardrails(organizationId: string, projectId: string): Promise<ProjectPRGuardrails> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/pr-guardrails`);
  },

  async updateProjectPRGuardrails(
    organizationId: string,
    projectId: string,
    data: Partial<Omit<ProjectPRGuardrails, 'id' | 'project_id' | 'created_at' | 'updated_at'>>
  ): Promise<ProjectPRGuardrails> {
    return fetchWithAuth(`/api/organizations/${organizationId}/projects/${projectId}/pr-guardrails`, {
      method: 'PUT',
      body: JSON.stringify(data),
    });
  },

  // Watchtower API
  async getWatchtowerSummary(
    packageName: string,
    projectDependencyId?: string,
    options?: { refresh?: boolean }
  ): Promise<WatchtowerSummary> {
    const params = new URLSearchParams();
    if (projectDependencyId) params.set('project_dependency_id', projectDependencyId);
    if (options?.refresh) params.set('refresh', 'true');
    const query = params.toString() ? `?${params.toString()}` : '';
    return fetchWithAuth(`/api/watchtower/${encodeURIComponent(packageName)}/summary${query}`);
  },

  async getWatchtowerCommits(
    packageName: string,
    limit: number = 50,
    offset: number = 0,
    organizationId?: string,
    projectDependencyId?: string,
    filter?: 'touches_imported',
    sort?: 'anomaly'
  ): Promise<WatchtowerCommitsResponse> {
    const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
    if (organizationId) params.set('organization_id', organizationId);
    if (projectDependencyId) params.set('project_dependency_id', projectDependencyId);
    if (filter === 'touches_imported') params.set('filter', 'touches_imported');
    if (sort === 'anomaly') params.set('sort', 'anomaly');
    return fetchWithAuth(
      `/api/watchtower/${encodeURIComponent(packageName)}/commits?${params.toString()}`
    );
  },

  async clearWatchtowerCommit(
    organizationId: string,
    projectId: string,
    dependencyId: string,
    commitSha: string
  ): Promise<void> {
    await fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${dependencyId}/cleared-commits`,
      { method: 'POST', body: JSON.stringify({ commit_sha: commitSha }) }
    );
  },

  async analyzeWatchtowerCommit(packageName: string, commitSha: string, repoFullName: string): Promise<{ analysis: string }> {
    return fetchWithAuth('/api/watchtower/analyze-commit', {
      method: 'POST',
      body: JSON.stringify({ packageName, commitSha, repoFullName }),
    });
  },

  async getWatchtowerContributors(packageName: string): Promise<any[]> {
    return fetchWithAuth(`/api/watchtower/${encodeURIComponent(packageName)}/contributors`);
  },

  async createWatchtowerBumpPR(
    organizationId: string,
    projectId: string,
    dependencyId: string,
    targetVersion?: string
  ): Promise<{ pr_url: string; pr_number: number; already_exists?: boolean }> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${dependencyId}/watchtower/bump`,
      {
        method: 'POST',
        body: targetVersion ? JSON.stringify({ target_version: targetVersion }) : undefined,
      }
    );
  },

  async createWatchtowerDecreasePR(
    organizationId: string,
    projectId: string,
    dependencyId: string
  ): Promise<{ pr_url: string; pr_number: number; already_exists?: boolean }> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${dependencyId}/watchtower/decrease`,
      { method: 'POST' }
    );
  },

  async createRemoveDependencyPR(
    organizationId: string,
    projectId: string,
    dependencyId: string
  ): Promise<{ pr_url: string; pr_number: number; already_exists?: boolean }> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/dependencies/${dependencyId}/remove-pr`,
      { method: 'POST' }
    );
  },

  // Banned Versions (org + team when projectId provided)
  async getBannedVersions(
    organizationId: string,
    dependencyId: string,
    projectId?: string
  ): Promise<{ banned_versions: BannedVersion[] }> {
    const params = new URLSearchParams({ dependency_id: dependencyId });
    if (projectId) params.set('project_id', projectId);
    return fetchWithAuth(
      `/api/organizations/${organizationId}/banned-versions?${params.toString()}`
    );
  },

  async banVersion(
    organizationId: string,
    dependencyId: string,
    bannedVersion: string,
    bumpToVersion: string
  ): Promise<BanVersionResponse> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/ban-version`,
      {
        method: 'POST',
        body: JSON.stringify({
          dependency_id: dependencyId,
          banned_version: bannedVersion,
          bump_to_version: bumpToVersion,
        }),
      }
    );
  },

  async banVersionTeam(
    organizationId: string,
    teamId: string,
    dependencyId: string,
    bannedVersion: string,
    bumpToVersion: string
  ): Promise<BanVersionResponse> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/teams/${teamId}/ban-version`,
      {
        method: 'POST',
        body: JSON.stringify({
          dependency_id: dependencyId,
          banned_version: bannedVersion,
          bump_to_version: bumpToVersion,
        }),
      }
    );
  },

  async removeBan(
    organizationId: string,
    banId: string
  ): Promise<{ message: string; id: string }> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/ban-version/${banId}`,
      { method: 'DELETE' }
    );
  },

  async getBumpScope(
    organizationId: string,
    projectId: string
  ): Promise<{ scope: 'org' | 'team' | 'project'; team_id?: string; team_name?: string }> {
    return fetchWithAuth(
      `/api/organizations/${organizationId}/projects/${projectId}/bump-scope`
    );
  },

  async bumpAllProjects(
    organizationId: string,
    dependencyId: string,
    targetVersion: string,
    teamId?: string
  ): Promise<BumpAllResponse> {
    const body: Record<string, string> = {
      dependency_id: dependencyId,
      target_version: targetVersion,
    };
    if (teamId) body.team_id = teamId;
    return fetchWithAuth(
      `/api/organizations/${organizationId}/bump-all`,
      {
        method: 'POST',
        body: JSON.stringify(body),
      }
    );
  },

  // Dependency Notes
  async getDependencyNotes(
    orgId: string,
    projectId: string,
    projectDependencyId: string
  ): Promise<{ notes: DependencyNote[] }> {
    return fetchWithAuth(
      `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/notes`
    );
  },

  async createDependencyNote(
    orgId: string,
    projectId: string,
    projectDependencyId: string,
    data: { content: string; is_warning?: boolean }
  ): Promise<DependencyNote> {
    return fetchWithAuth(
      `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/notes`,
      { method: 'POST', body: JSON.stringify(data) }
    );
  },

  async deleteDependencyNote(
    orgId: string,
    projectId: string,
    projectDependencyId: string,
    noteId: string
  ): Promise<void> {
    return fetchWithAuth(
      `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/notes/${noteId}`,
      { method: 'DELETE' }
    );
  },

  async addNoteReaction(
    orgId: string,
    projectId: string,
    projectDependencyId: string,
    noteId: string,
    emoji: string
  ): Promise<{ id: string; note_id: string; user_id: string; emoji: string; created_at: string }> {
    return fetchWithAuth(
      `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/notes/${noteId}/reactions`,
      { method: 'POST', body: JSON.stringify({ emoji: emoji.trim() }) }
    );
  },

  async removeNoteReaction(
    orgId: string,
    projectId: string,
    projectDependencyId: string,
    noteId: string,
    reactionId: string
  ): Promise<void> {
    return fetchWithAuth(
      `/api/organizations/${orgId}/projects/${projectId}/dependencies/${projectDependencyId}/notes/${noteId}/reactions/${reactionId}`,
      { method: 'DELETE' }
    );
  },

  async deprecateDependency(
    orgId: string,
    dependencyId: string,
    recommendedAlternative: string
  ): Promise<{ id: string; organization_id: string; dependency_id: string; recommended_alternative: string; deprecated_by: string; created_at: string }> {
    return fetchWithAuth(
      `/api/organizations/${orgId}/deprecations`,
      {
        method: 'POST',
        body: JSON.stringify({
          dependency_id: dependencyId,
          recommended_alternative: recommendedAlternative,
        }),
      }
    );
  },

  async deprecateDependencyTeam(
    orgId: string,
    teamId: string,
    dependencyId: string,
    recommendedAlternative: string
  ): Promise<Record<string, unknown>> {
    return fetchWithAuth(
      `/api/organizations/${orgId}/teams/${teamId}/deprecations`,
      {
        method: 'POST',
        body: JSON.stringify({
          dependency_id: dependencyId,
          recommended_alternative: recommendedAlternative,
        }),
      }
    );
  },

  async removeDeprecation(
    orgId: string,
    dependencyId: string
  ): Promise<{ success: boolean }> {
    return fetchWithAuth(
      `/api/organizations/${orgId}/deprecations/${dependencyId}`,
      { method: 'DELETE' }
    );
  },

  async removeDeprecationTeam(
    orgId: string,
    teamId: string,
    dependencyId: string
  ): Promise<{ success: boolean }> {
    return fetchWithAuth(
      `/api/organizations/${orgId}/teams/${teamId}/deprecations/${dependencyId}`,
      { method: 'DELETE' }
    );
  },
};

export interface Team {
  id: string;
  organization_id: string;
  name: string;
  description?: string | null;
  avatar_url?: string | null;
  created_at: string;
  updated_at: string;
  member_count?: number;
  project_count?: number;
}

export interface TeamPermissions {
  view_overview: boolean;
  manage_projects: boolean;
  manage_members: boolean;
  view_settings: boolean;
  view_roles: boolean;
  edit_roles: boolean;
  manage_notification_settings: boolean;
  view_members?: boolean;
  add_members?: boolean;
  kick_members?: boolean;
}

export interface TeamWithRole extends Team {
  role?: string;
  role_display_name?: string | null;
  role_color?: string | null;
  user_rank?: number | null;
  permissions?: TeamPermissions;
}

export interface TeamRole {
  id: string;
  team_id: string;
  name: string;
  display_name?: string | null;
  color?: string | null;
  is_default: boolean;
  display_order: number;
  permissions: TeamPermissions;
  created_at: string;
  updated_at: string;
}

export interface TeamMember {
  user_id: string;
  email: string;
  full_name?: string | null;
  avatar_url?: string | null;
  role: string;
  role_display_name?: string | null;
  role_color?: string | null;
  rank?: number | null;
  org_rank?: number | null;
  permissions?: TeamPermissions;
  created_at?: string;
}

export type AssetTier = 'CROWN_JEWELS' | 'EXTERNAL' | 'INTERNAL' | 'NON_PRODUCTION';

export interface Project {
  id: string;
  organization_id: string;
  name: string;
  team_id?: string | null;
  health_score: number;
  status?: string;
  is_compliant?: boolean;
  auto_bump?: boolean;
  created_at: string;
  updated_at: string;
  team_name?: string | null;
  team_ids?: string[];
  team_names?: string[];
  owner_team_id?: string | null;
  owner_team_name?: string | null;
  dependencies_count?: number;
  framework?: string | null;
  alerts_count?: number;
  repo_status?: string | null;
  extraction_step?: string | null;
  extraction_error?: string | null;
  role?: string;
  asset_tier?: AssetTier;
}

export interface ProjectRepository {
  repo_full_name: string;
  default_branch: string;
  status: 'pending' | 'initializing' | 'extracting' | 'analyzing' | 'finalizing' | 'ready' | 'error';
  dependencies_count?: number;
  analyzing_count?: number;
  package_json_path?: string;
  extraction_step?: string | null;
  extraction_error?: string | null;
  pull_request_comments_enabled?: boolean;
  connected_at?: string | null;
}

export interface OpenssfCheck {
  name: string;
  score?: number;
  reason?: string;
}

export interface ProjectDependencyAnalysis {
  status: 'pending' | 'analyzing' | 'ready' | 'error';
  score: number | null;
  score_breakdown?: {
    openssf_penalty: number | null;
    popularity_penalty: number | null;
    maintenance_penalty: number | null;
  };
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  openssf_score: number | null;
  openssf_data?: { score?: number; checks?: OpenssfCheck[] } | null;
  weekly_downloads: number | null;
  last_published_at: string | null;
  latest_release_date?: string | null;
  releases_last_12_months?: number | null;
  analyzed_at: string | null;
}

export interface ProjectDependency {
  id: string;
  project_id: string;
  dependency_id?: string;
  dependency_version_id?: string;
  name: string;
  version: string;
  license: string | null;
  github_url: string | null;
  is_direct: boolean;
  source: 'dependencies' | 'devDependencies' | 'transitive';
  /** For transitive deps: "parentName@parentVersion" of the package that brings this one in. */
  parent_package?: string | null;
  environment?: 'prod' | 'dev' | null;
  is_watching: boolean;
  watchtower_cleared_at?: string | null;
  files_importing_count?: number;
  imported_functions?: string[];
  imported_file_paths?: string[];
  ai_usage_summary?: string | null;
  ai_usage_analyzed_at?: string | null;
  other_projects_using_count?: number;
  other_projects_using_names?: string[];
  description?: string | null;
  created_at: string;
  analysis?: ProjectDependencyAnalysis | null;
  deprecation?: {
    recommended_alternative: string;
    deprecated_by: string | null;
    created_at: string;
    scope?: 'organization' | 'team';
    team_id?: string;
  } | null;
  remove_pr_url?: string | null;
  remove_pr_number?: number | null;
  version_checks?: {
    registry_integrity_status: string | null;
    registry_integrity_reason: string | null;
    install_scripts_status: string | null;
    install_scripts_reason: string | null;
    entropy_analysis_status: string | null;
    entropy_analysis_reason: string | null;
  } | null;
  is_current_version_banned?: boolean;
}

export interface DependencyVersionVulnerability {
  osv_id: string;
  severity: string;
  summary: string | null;
  aliases: string[];
  /** Present for direct vulnerabilities (fixed in this package); not set for transitive. */
  fixed_versions?: string[];
  /** Present for transitive vulnerabilities: name of the dependency that brought in this vuln. */
  from_package?: string;
  /** Depscore (0-100) when available from project vulnerability data. */
  depscore?: number | null;
  cvss_score?: number | null;
  epss_score?: number | null;
  cisa_kev?: boolean;
  is_reachable?: boolean;
}

export interface DependencyVersionItem {
  version: string;
  vulnCount: number | null;
  vulnerabilities: DependencyVersionVulnerability[];
  transitiveVulnCount?: number;
  transitiveVulnerabilities?: DependencyVersionVulnerability[];
  totalVulnCount?: number;
  registry_integrity_status: 'pass' | 'warning' | 'fail' | null;
  registry_integrity_reason: string | null;
  install_scripts_status: 'pass' | 'warning' | 'fail' | null;
  install_scripts_reason: string | null;
  entropy_analysis_status: 'pass' | 'warning' | 'fail' | null;
  entropy_analysis_reason: string | null;
}

export interface WatchtowerPRItem {
  target_version: string;
  pr_url: string;
  pr_number: number;
}

export interface DependencyVersionsResponse {
  versions: DependencyVersionItem[];
  currentVersion: string;
  latestVersion: string;
  prs: WatchtowerPRItem[];
  bannedVersions?: string[];
  /** Present when request used limit/offset (paginated); total count of versions. */
  total?: number;
}

export interface SupplyChainChild {
  name: string;
  version: string;
  dependency_version_id: string;
  score: number | null;
  license: string | null;
  critical_vulns: number;
  high_vulns: number;
  medium_vulns: number;
  low_vulns: number;
  vulnerabilities: Array<{ osv_id: string; severity: string; summary: string | null; aliases: string[]; is_reachable?: boolean }>;
}

export interface SupplyChainAncestorNode {
  name: string;
  version: string;
  dependency_version_id: string;
  is_direct: boolean;
}

export interface SupplyChainAvailableVersion {
  dependency_version_id: string;
  version: string;
}

export interface SupplyChainBumpPr {
  target_version: string;
  pr_url: string;
  pr_number: number;
}

export interface VersionSecurityChecks {
  registry_integrity_status: string | null;
  install_scripts_status: string | null;
  entropy_analysis_status: string | null;
}

export interface SupplyChainVersionSecurityData {
  onWatchtower: boolean;
  quarantinedVersions: string[];
  securityChecks: Record<string, VersionSecurityChecks>;
}

export interface VersionVulnerabilitySummaryItem {
  hasDirect: boolean;
  hasTransitive: boolean;
}

export interface SupplyChainResponse {
  parent: {
    name: string;
    version: string;
    dependency_id: string | null;
    dependency_version_id: string;
    is_direct: boolean;
    license: string | null;
    vulnerabilities: Array<{
      osv_id: string;
      severity: string;
      summary: string | null;
      aliases: string[];
      affected_versions?: unknown;
      fixed_versions?: string[];
    }>;
    /** For the graph only: vulns that affect the current version. */
    vulnerabilities_affecting_current_version?: Array<{
      osv_id: string;
      severity: string;
      summary: string | null;
      aliases: string[];
      affected_versions?: unknown;
      fixed_versions?: string[];
    }>;
    files_importing_count?: number;
    remove_pr_url?: string | null;
    remove_pr_number?: number | null;
  };
  children: SupplyChainChild[];
  ancestors: SupplyChainAncestorNode[][];
  availableVersions: SupplyChainAvailableVersion[];
  bumpPrs: SupplyChainBumpPr[];
  /** Present when org has this package on watchtower: security checks and quarantined versions per version. */
  versionSecurityData?: SupplyChainVersionSecurityData;
  /** Per-version vulnerability flags for dropdown (direct and transitive). Key is version string. */
  versionVulnerabilitySummary?: Record<string, VersionVulnerabilitySummaryItem>;
  /** Banned versions for this dependency (org + team when project in context). Included in initial load to avoid a second request. */
  banned_versions?: BannedVersion[];
}

export interface SupplyChainVersionResponse {
  version: string;
  children: SupplyChainChild[];
  /** Vulnerabilities that affect this version (when viewing alternate version). */
  vulnerabilities?: Array<{
    osv_id: string;
    severity: string;
    summary: string | null;
    aliases: string[];
    affected_versions?: unknown;
    fixed_versions?: string[];
  }>;
}

export interface LatestSafeVersionResponse {
  safeVersion: string | null;
  safeVersionId: string | null;
  isCurrent: boolean;
  severity: string;
  versionsChecked: number;
  message: string | null;
}

export interface DependencyNoteReaction {
  emoji: string;
  count: number;
  user_reacted: boolean;
  reaction_id: string | null;
  /** Display names of who reacted (backend sends "You" for current user). */
  reactor_names?: string[];
}

export interface DependencyNote {
  id: string;
  content: string;
  is_warning: boolean;
  created_at: string;
  can_delete?: boolean;
  reactions?: DependencyNoteReaction[];
  author: {
    id: string;
    name: string | null;
    avatar_url: string | null;
    org_role: string | null;
    org_role_display_name: string | null;
    org_role_color: string | null;
  };
}

export interface ProjectImportStatus {
  status: 'not_connected' | 'initializing' | 'extracting' | 'analyzing' | 'finalizing' | 'ready' | 'error';
  total: number;
  ready: number;
  analyzing: number;
  pending: number;
  error: number;
  extraction_step?: string | null;
  extraction_error?: string | null;
}

export interface ProjectVulnerability {
  id: string;
  osv_id: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  summary: string | null;
  details: string | null;
  aliases: string[];
  fixed_versions: string[];
  published_at: string | null;
  modified_at: string | null;
  dependency_id: string;
  dependency_name: string;
  dependency_version: string;
  /** When false, vulnerability is not reachable from application code. Optional for backward compat. */
  is_reachable?: boolean;
  epss_score?: number;
  cvss_score?: number;
  cisa_kev?: boolean;
  depscore?: number;
}

export interface ProjectPermissions {
  view_overview: boolean;
  view_dependencies: boolean;
  view_members: boolean;
  manage_members: boolean;
  view_settings: boolean;
  edit_settings: boolean;
  /** True when user has org manage_teams_and_projects or team manage_projects (owner team). Required for watchtower management. */
  can_manage_watchtower?: boolean;
  view_watchlist?: boolean;
}

export interface ProjectWithRole extends Project {
  role?: string;
  permissions?: ProjectPermissions;
}

export interface ProjectRole {
  id: string;
  project_id: string;
  name: string;
  display_name?: string | null;
  is_default: boolean;
  display_order: number;
  permissions: ProjectPermissions;
  created_at: string;
  updated_at: string;
}

export interface ProjectMember {
  user_id: string;
  full_name?: string | null;
  avatar_url?: string | null;
  email?: string | null;
  role?: string;
  role_display_name?: string | null;
  permissions?: ProjectPermissions;
  membership_type: 'direct' | 'team';
  teams?: string[];
  created_at?: string;
}

export interface ProjectMembersResponse {
  direct_members: ProjectMember[];
  team_members: ProjectMember[];
}

export interface ProjectContributingTeam {
  id: string;
  name: string;
  description?: string | null;
  avatar_url?: string | null;
  added_at?: string;
}

export interface ProjectTeamsResponse {
  owner_team: {
    id: string;
    name: string;
    description?: string | null;
    avatar_url?: string | null;
  } | null;
  contributing_teams: ProjectContributingTeam[];
}

export interface OrganizationNotificationRule {
  id: string;
  name: string;
  triggerType: 'weekly_digest' | 'vulnerability_discovered' | 'custom_code_pipeline';
  minDepscoreThreshold?: number;
  customCode?: string;
  destinations: Array<{ integrationType: string; targetId: string }>;
  active: boolean;
  createdByUserId?: string;
  createdByName?: string;
}

export interface OrganizationPolicies {
  policy_code: string;
  /** @deprecated Policy is defined as code; kept for backward compat. */
  accepted_licenses?: string[];
  rejected_licenses?: string[];
  slsa_enforcement?: 'none' | 'recommended' | 'require_provenance' | 'require_attestations' | 'require_signed';
  slsa_level?: number | null;
}

export interface Activity {
  id: string;
  organization_id: string;
  user_id: string;
  activity_type: string;
  description: string;
  metadata: Record<string, any>;
  created_at: string;
  user: {
    email: string;
    full_name?: string | null;
    avatar_url?: string | null;
  } | null;
}

export interface AegisThread {
  id: string;
  organization_id: string;
  user_id: string;
  title: string;
  created_at: string;
  updated_at: string;
}

export interface AegisMessage {
  id: string;
  thread_id: string;
  role: 'user' | 'assistant';
  content: string;
  metadata: Record<string, any>;
  created_at: string;
}

export interface AegisMessageResponse {
  threadId: string;
  type: 'action' | 'conversation';
  message: string;
  action?: string;
  result?: any;
}

export interface AegisActivityLog {
  id: string;
  organization_id: string;
  timestamp: string;
  request_text: string;
  action_performed: string | null;
  result_json: Record<string, any>;
}

export interface AegisAutomation {
  id: string;
  organization_id: string;
  name: string;
  description: string | null;
  schedule: string;
  enabled: boolean;
  last_run_at: string | null;
  next_run_at: string | null;
  created_at: string;
}

export interface AegisInboxMessage {
  id: string;
  organization_id: string;
  user_id: string | null;
  type: 'alert' | 'message' | 'task' | 'approval' | 'report';
  title: string;
  content: string;
  metadata: Record<string, any>;
  read: boolean;
  created_at: string;
}

export interface ProjectPolicyException {
  id: string;
  project_id: string;
  organization_id: string;
  requested_by: string;
  status: 'pending' | 'accepted' | 'rejected' | 'revoked';
  reason: string;
  policy_type?: 'compliance' | 'pull_request' | 'full';
  additional_licenses: string[];
  requested_policy_code?: string | null;
  base_policy_code?: string | null;
  slsa_enforcement?: 'none' | 'recommended' | 'require_provenance' | 'require_attestations' | 'require_signed' | null;
  slsa_level?: number | null;
  reviewed_by?: string | null;
  reviewed_at?: string | null;
  revoked_by?: string | null;
  revoked_at?: string | null;
  created_at: string;
  updated_at: string;
  project_name?: string;
  project_framework?: string | null;
  requester?: {
    email: string;
    full_name: string | null;
    avatar_url?: string | null;
    role?: string;
    role_display_name?: string | null;
    role_color?: string | null;
  };
}

/** Pending exception for project policies (policy-as-code). */
export interface ProjectPolicyPendingException {
  id: string;
  policy_type?: 'compliance' | 'pull_request' | 'full';
  requested_policy_code: string;
  base_policy_code: string;
  reason: string;
  requested_by: string;
  created_at: string;
  updated_at: string;
}

export interface ProjectEffectivePolicies {
  inherited_policy_code?: string;
  effective_policy_code?: string;
  pending_exception?: ProjectPolicyPendingException | null;
  inherited: {
    accepted_licenses: string[];
    slsa_enforcement: 'none' | 'recommended' | 'require_provenance' | 'require_attestations' | 'require_signed';
    slsa_level: number | null;
  };
  effective: {
    accepted_licenses: string[];
    slsa_enforcement: 'none' | 'recommended' | 'require_provenance' | 'require_attestations' | 'require_signed';
    slsa_level: number | null;
  };
  accepted_exceptions: ProjectPolicyException[];
  pending_exceptions: ProjectPolicyException[];
  revoked_exceptions?: ProjectPolicyException[];
}

export interface ProjectPRGuardrails {
  id?: string;
  project_id: string;
  block_critical_vulns: boolean;
  block_high_vulns: boolean;
  block_medium_vulns: boolean;
  block_low_vulns: boolean;
  block_policy_violations: boolean;
  block_transitive_vulns: boolean;
  created_at?: string;
  updated_at?: string;
}

// Banned versions types
export interface BannedVersion {
  id: string;
  dependency_id: string;
  banned_version: string;
  bump_to_version: string;
  banned_by: string;
  created_at: string;
  source?: 'org' | 'team';
  team_id?: string;
}

export interface BanVersionResponse {
  ban: BannedVersion;
  affected_projects: number;
  pr_results: Array<{
    project_id: string;
    pr_url?: string;
    pr_number?: number;
    error?: string;
  }>;
}

export interface BumpAllResponse {
  affected_projects: number;
  pr_results: Array<{
    project_id: string;
    current_version?: string;
    pr_url?: string;
    pr_number?: number;
    error?: string;
  }>;
}

// Watchtower types
export interface WatchtowerSummary {
  name: string;
  status: 'pending' | 'analyzing' | 'ready' | 'error';
  latest_version?: string | null;
  latest_release_date?: string | null;
  latest_allowed_version?: string | null;
  quarantine_next_release?: boolean;
  is_current_version_quarantined?: boolean;
  quarantine_until?: string | null;
  bump_pr_url?: string | null;
  decrease_pr_url?: string | null;
  registry_integrity_status?: 'pass' | 'warning' | 'fail' | null;
  registry_integrity_reason?: string | null;
  install_scripts_status?: 'pass' | 'warning' | 'fail' | null;
  install_scripts_reason?: string | null;
  entropy_analysis_status?: 'pass' | 'warning' | 'fail' | null;
  entropy_analysis_reason?: string | null;
  maintainer_analysis_status?: 'pass' | 'warning' | 'fail' | null;
  quarantine_expires_at?: string | null;
  analyzed_at?: string | null;
  commits_count: number;
  contributors_count: number;
  anomalies_count: number;
  top_anomaly_score: number;
}

export interface WatchtowerCommit {
  id: string;
  sha: string;
  author: string;
  author_email: string;
  message: string;
  timestamp: string;
  lines_added: number;
  lines_deleted: number;
  files_changed: number;
  anomaly?: {
    score: number;
    breakdown: Array<{ factor: string; points: number; reason: string }>;
  } | null;
  touched_functions?: string[];
  touches_imported_functions?: string[];
}

export interface WatchtowerCommitsResponse {
  commits: WatchtowerCommit[];
  total: number;
  limit: number;
  offset: number;
}