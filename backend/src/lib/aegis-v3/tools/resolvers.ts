import type { SupabaseClient } from '@supabase/supabase-js';

// Resolvers translate the user-facing names that Aegis (and the user) speak in
// — "deptex-test-npm", "minimist", "CVE-2021-44906" — into the UUIDs we need
// to query against. The model never sees a UUID; it never invents one.
//
// Every resolver returns either a populated row or a structured `error` string
// shaped so the model's natural follow-up is "ask the user to clarify" or
// "drop the filter and retry," not "fabricate something."

type ResolveResult<T> = T | { error: string };
type ProjectRef = { id: string; name: string };
type TeamRef = { id: string; name: string };
type ProjectDependencyRef = {
  id: string;
  name: string;
  version: string | null;
  projectId: string;
  projectName: string;
};
type ProjectVulnerabilityRef = {
  vulnerabilityId: string;
  osvId: string;
  projectId: string;
  projectName: string;
};

function formatList(items: string[], max = 8): string {
  if (items.length <= max) return items.join(', ');
  return `${items.slice(0, max).join(', ')}, ... (+${items.length - max} more)`;
}

export async function resolveProject(
  name: string,
  orgId: string,
  supabase: SupabaseClient,
): Promise<ResolveResult<ProjectRef>> {
  const trimmed = (name ?? '').trim();
  if (!trimmed) return { error: 'Project name is required.' };

  const { data: exact } = await supabase
    .from('projects')
    .select('id, name')
    .eq('organization_id', orgId)
    .eq('name', trimmed)
    .limit(2);
  if (exact && exact.length === 1) {
    return { id: exact[0].id as string, name: exact[0].name as string };
  }

  const { data: fuzzy } = await supabase
    .from('projects')
    .select('id, name')
    .eq('organization_id', orgId)
    .ilike('name', `%${trimmed}%`)
    .limit(10);

  if (!fuzzy || fuzzy.length === 0) {
    const { data: all } = await supabase
      .from('projects')
      .select('name')
      .eq('organization_id', orgId)
      .order('name', { ascending: true });
    const names = (all ?? []).map((p: { name: string }) => p.name);
    return {
      error:
        names.length === 0
          ? `No projects exist in this organization yet.`
          : `No project matches "${trimmed}". Available projects: ${formatList(names)}.`,
    };
  }

  if (fuzzy.length === 1) {
    return { id: fuzzy[0].id as string, name: fuzzy[0].name as string };
  }

  const matches = fuzzy.map((p: { name: string }) => p.name);
  return {
    error: `Multiple projects match "${trimmed}": ${matches.join(', ')}. Ask the user which one.`,
  };
}

export async function resolveTeam(
  name: string,
  orgId: string,
  supabase: SupabaseClient,
): Promise<ResolveResult<TeamRef>> {
  const trimmed = (name ?? '').trim();
  if (!trimmed) return { error: 'Team name is required.' };

  const { data: exact } = await supabase
    .from('teams')
    .select('id, name')
    .eq('organization_id', orgId)
    .eq('name', trimmed)
    .limit(2);
  if (exact && exact.length === 1) {
    return { id: exact[0].id as string, name: exact[0].name as string };
  }

  const { data: fuzzy } = await supabase
    .from('teams')
    .select('id, name')
    .eq('organization_id', orgId)
    .ilike('name', `%${trimmed}%`)
    .limit(10);

  if (!fuzzy || fuzzy.length === 0) {
    const { data: all } = await supabase
      .from('teams')
      .select('name')
      .eq('organization_id', orgId)
      .order('name', { ascending: true });
    const names = (all ?? []).map((t: { name: string }) => t.name);
    return {
      error:
        names.length === 0
          ? `No teams exist in this organization yet.`
          : `No team matches "${trimmed}". Available teams: ${formatList(names)}.`,
    };
  }

  if (fuzzy.length === 1) {
    return { id: fuzzy[0].id as string, name: fuzzy[0].name as string };
  }

  const matches = fuzzy.map((t: { name: string }) => t.name);
  return {
    error: `Multiple teams match "${trimmed}": ${matches.join(', ')}. Ask the user which one.`,
  };
}

export async function resolveProjectDependency(
  projectName: string,
  packageName: string,
  orgId: string,
  supabase: SupabaseClient,
): Promise<ResolveResult<ProjectDependencyRef>> {
  const project = await resolveProject(projectName, orgId, supabase);
  if ('error' in project) return project;

  const trimmed = (packageName ?? '').trim();
  if (!trimmed) return { error: 'Package name is required.' };

  const { data: exact } = await supabase
    .from('project_dependencies')
    .select('id, name, version')
    .eq('project_id', project.id)
    .eq('name', trimmed)
    .is('removed_at', null)
    .limit(2);
  if (exact && exact.length === 1) {
    return {
      id: exact[0].id as string,
      name: exact[0].name as string,
      version: (exact[0] as { version: string | null }).version,
      projectId: project.id,
      projectName: project.name,
    };
  }

  const { data: fuzzy } = await supabase
    .from('project_dependencies')
    .select('id, name, version')
    .eq('project_id', project.id)
    .is('removed_at', null)
    .ilike('name', `%${trimmed}%`)
    .limit(10);

  if (!fuzzy || fuzzy.length === 0) {
    return {
      error: `No dependency matches "${trimmed}" in project "${project.name}".`,
    };
  }

  if (fuzzy.length === 1) {
    return {
      id: fuzzy[0].id as string,
      name: fuzzy[0].name as string,
      version: (fuzzy[0] as { version: string | null }).version,
      projectId: project.id,
      projectName: project.name,
    };
  }

  const matches = fuzzy.map((d: { name: string }) => d.name);
  return {
    error: `Multiple dependencies in "${project.name}" match "${trimmed}": ${matches.join(', ')}. Ask the user which one.`,
  };
}

export async function resolveProjectVulnerability(
  projectName: string,
  cveOrOsvId: string,
  orgId: string,
  supabase: SupabaseClient,
): Promise<ResolveResult<ProjectVulnerabilityRef>> {
  const project = await resolveProject(projectName, orgId, supabase);
  if ('error' in project) return project;

  const trimmed = (cveOrOsvId ?? '').trim();
  if (!trimmed) return { error: 'CVE or OSV id is required.' };

  let query = supabase
    .from('project_dependency_vulnerabilities')
    .select('id, osv_id')
    .eq('project_id', project.id)
    .limit(2);

  if (trimmed.toUpperCase().startsWith('CVE-')) {
    query = (query as { contains: (col: string, val: unknown) => typeof query }).contains(
      'aliases',
      [trimmed.toUpperCase()],
    );
  } else {
    query = query.eq('osv_id', trimmed);
  }

  const { data: rows } = await query;
  if (!rows || rows.length === 0) {
    return {
      error: `Vulnerability "${trimmed}" not found in project "${project.name}". Pass a CVE/OSV id from get_project_vulnerabilities.`,
    };
  }

  return {
    vulnerabilityId: rows[0].id as string,
    osvId: rows[0].osv_id as string,
    projectId: project.id,
    projectName: project.name,
  };
}
