import { vi } from 'vitest';

export const api = {
  getOrganizationRoles: vi.fn(),
  getOrganization: vi.fn(),
  getUserProfile: vi.fn(),
  getProject: vi.fn(),
  getTeam: vi.fn(),
  getOrganizationPermissions: vi.fn(),
  getDependencyOverview: vi.fn(),
  getProjectPolicies: vi.fn(),
  createRemoveDependencyPR: vi.fn(),
  analyzeDependencyUsage: vi.fn(),
  getCachedProject: vi.fn(),
  getCachedOrganization: vi.fn(),
  getCachedDependency: vi.fn(),
};
