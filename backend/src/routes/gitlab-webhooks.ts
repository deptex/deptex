/**
 * 8I: GitLab Webhook Handler
 * Handles Push Hook and Merge Request Hook events from GitLab.
 */

// @ts-nocheck
import express from 'express';
import { supabase } from '../lib/supabase';
import { queueExtractionJob, queueASTParsingJob } from '../lib/redis';
import { invalidateProjectCaches } from '../lib/cache';
import { detectAffectedWorkspaces, isFileInWorkspace } from '../lib/manifest-registry';
import { checkRateLimit } from '../lib/rate-limit';
import { runPRCheck } from '../lib/policy-engine';
import { getVulnCountsForPackageVersion, exceedsThreshold, type VulnCounts } from '../lib/vuln-counts';
import { getEffectivePolicies, isLicenseAllowed } from '../lib/project-policies';

const router = express.Router();

const DEPTEX_COMMENT_MARKER = '<!-- deptex-pr-check -->';
const MAX_EXTRACTION_PER_PUSH = 10;

async function verifyGitLabWebhookToken(req: express.Request): Promise<{ valid: boolean; repoFullName: string | null }> {
  const token = req.headers['x-gitlab-token'] as string;
  const repoFullName = req.body?.project?.path_with_namespace;
  if (!token || !repoFullName) return { valid: false, repoFullName: null };

  const { data } = await supabase
    .from('project_repositories')
    .select('webhook_secret')
    .eq('repo_full_name', repoFullName)
    .eq('provider', 'gitlab');

  const valid = (data ?? []).some((r: any) => r.webhook_secret === token);
  return { valid, repoFullName };
}

async function deduplicateDelivery(deliveryId: string | undefined): Promise<boolean> {
  if (!deliveryId) return false;
  try {
    const { Redis } = await import('@upstash/redis');
    const redis = new Redis({
      url: process.env.UPSTASH_REDIS_URL!,
      token: process.env.UPSTASH_REDIS_TOKEN!,
    });
    const key = `webhook-delivery:${deliveryId}`;
    const existing = await redis.get(key);
    if (existing) return true;
    await redis.set(key, '1', { ex: 3600 });
    return false;
  } catch {
    return false;
  }
}

async function recordWebhookDelivery(
  deliveryId: string | undefined,
  eventType: string,
  action: string | undefined,
  repoFullName: string | null,
  payloadSize: number,
  status: string = 'received'
) {
  try {
    await supabase.from('webhook_deliveries').insert({
      delivery_id: deliveryId || 'unknown',
      provider: 'gitlab',
      event_type: eventType,
      action,
      repo_full_name: repoFullName,
      processing_status: status,
      payload_size_bytes: payloadSize,
    });
  } catch {}
}

async function getGitLabFileContent(
  accessToken: string,
  projectId: number,
  filePath: string,
  ref: string
): Promise<string | null> {
  try {
    const encodedPath = encodeURIComponent(filePath);
    const res = await fetch(
      `https://gitlab.com/api/v4/projects/${projectId}/repository/files/${encodedPath}?ref=${encodeURIComponent(ref)}`,
      { headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'Deptex-App' } }
    );
    if (!res.ok) return null;
    const data = (await res.json()) as { content: string; encoding: string };
    if (data.encoding === 'base64') return Buffer.from(data.content, 'base64').toString('utf-8');
    return data.content;
  } catch {
    return null;
  }
}

async function getGitLabCompareChangedFiles(
  accessToken: string,
  projectId: number,
  from: string,
  to: string
): Promise<string[]> {
  try {
    const res = await fetch(
      `https://gitlab.com/api/v4/projects/${projectId}/repository/compare?from=${encodeURIComponent(from)}&to=${encodeURIComponent(to)}`,
      { headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'Deptex-App' } }
    );
    if (!res.ok) return [];
    const data = (await res.json()) as { diffs?: Array<{ new_path: string; old_path: string }> };
    const files = new Set<string>();
    for (const d of data.diffs ?? []) {
      if (d.new_path) files.add(d.new_path);
      if (d.old_path && d.old_path !== d.new_path) files.add(d.old_path);
    }
    return Array.from(files);
  } catch {
    return [];
  }
}

async function getGitLabOAuthToken(repoFullName: string): Promise<{ token: string; gitlabProjectId: number } | null> {
  const { data: repos } = await supabase
    .from('project_repositories')
    .select('project_id, projects(organization_id)')
    .eq('repo_full_name', repoFullName)
    .eq('provider', 'gitlab')
    .limit(1);

  if (!repos?.length) return null;
  const orgId = Array.isArray((repos[0] as any).projects)
    ? (repos[0] as any).projects[0]?.organization_id
    : (repos[0] as any).projects?.organization_id;
  if (!orgId) return null;

  const { data: integration } = await supabase
    .from('organization_integrations')
    .select('access_token, metadata')
    .eq('organization_id', orgId)
    .eq('provider', 'gitlab')
    .single();

  if (!integration?.access_token) return null;

  const gitlabProjectId = integration.metadata?.project_id ?? 0;
  return { token: integration.access_token, gitlabProjectId };
}

async function createGitLabCommitStatus(
  accessToken: string,
  projectId: number,
  sha: string,
  state: 'pending' | 'running' | 'success' | 'failed',
  name: string,
  description: string,
  targetUrl?: string
) {
  try {
    const body: Record<string, unknown> = { state, name, description };
    if (targetUrl) body.target_url = targetUrl;
    await fetch(
      `https://gitlab.com/api/v4/projects/${projectId}/statuses/${encodeURIComponent(sha)}`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'User-Agent': 'Deptex-App',
        },
        body: JSON.stringify(body),
      }
    );
  } catch (err: any) {
    console.error('[gitlab-webhook] Failed to create commit status:', err?.message);
  }
}

async function findAndEditGitLabMRNote(
  accessToken: string,
  gitlabProjectId: number,
  mrIid: number,
  newBody: string
): Promise<void> {
  try {
    const res = await fetch(
      `https://gitlab.com/api/v4/projects/${gitlabProjectId}/merge_requests/${mrIid}/notes?per_page=100`,
      { headers: { Authorization: `Bearer ${accessToken}`, 'User-Agent': 'Deptex-App' } }
    );
    if (!res.ok) {
      await createGitLabMRNote(accessToken, gitlabProjectId, mrIid, newBody);
      return;
    }
    const notes = (await res.json()) as Array<{ id: number; body: string }>;
    const existing = notes.find(n => n.body.includes(DEPTEX_COMMENT_MARKER));
    if (existing) {
      await fetch(
        `https://gitlab.com/api/v4/projects/${gitlabProjectId}/merge_requests/${mrIid}/notes/${existing.id}`,
        {
          method: 'PUT',
          headers: {
            Authorization: `Bearer ${accessToken}`,
            'Content-Type': 'application/json',
            'User-Agent': 'Deptex-App',
          },
          body: JSON.stringify({ body: newBody }),
        }
      );
    } else {
      await createGitLabMRNote(accessToken, gitlabProjectId, mrIid, newBody);
    }
  } catch (err: any) {
    console.error('[gitlab-webhook] Failed to find/edit MR note:', err?.message);
    await createGitLabMRNote(accessToken, gitlabProjectId, mrIid, newBody);
  }
}

async function createGitLabMRNote(
  accessToken: string,
  gitlabProjectId: number,
  mrIid: number,
  body: string
): Promise<void> {
  try {
    await fetch(
      `https://gitlab.com/api/v4/projects/${gitlabProjectId}/merge_requests/${mrIid}/notes`,
      {
        method: 'POST',
        headers: {
          Authorization: `Bearer ${accessToken}`,
          'Content-Type': 'application/json',
          'User-Agent': 'Deptex-App',
        },
        body: JSON.stringify({ body }),
      }
    );
  } catch (err: any) {
    console.error('[gitlab-webhook] Failed to create MR note:', err?.message);
  }
}

async function handleGitLabPushEvent(payload: any): Promise<void> {
  const repoFullName = payload?.project?.path_with_namespace;
  const ref = payload?.ref;
  const before = payload?.before;
  const after = payload?.after;
  const gitlabProjectId = payload?.project?.id;

  if (!repoFullName || !ref || !after || /^0+$/.test(String(after))) return;

  const { data: rows } = await supabase
    .from('project_repositories')
    .select('project_id, repo_full_name, default_branch, package_json_path, sync_frequency, status, integration_id, ecosystem, projects(organization_id)')
    .eq('repo_full_name', repoFullName)
    .eq('provider', 'gitlab');

  const expectedRef = (branch: string) => `refs/heads/${branch}`;
  const projects = (rows ?? []).filter(
    (r: any) => r.default_branch && ref === expectedRef(r.default_branch)
  );
  if (projects.length === 0) return;

  const auth = await getGitLabOAuthToken(repoFullName);
  let changedFiles: string[] = [];
  if (auth && before && !/^0+$/.test(String(before))) {
    changedFiles = await getGitLabCompareChangedFiles(auth.token, gitlabProjectId, before, after);
  }

  const affectedWorkspaces = detectAffectedWorkspaces(changedFiles);
  const forceFullExtraction = changedFiles.length === 0;

  let extractionCount = 0;

  for (const row of projects as any[]) {
    const activeStatuses = ['pending', 'initializing', 'ready', 'error', 'cancelled'];
    if (!activeStatuses.includes(row.status)) continue;

    const orgId = Array.isArray(row.projects) ? row.projects[0]?.organization_id : row.projects?.organization_id;
    if (!orgId) continue;

    const workspace = (row.package_json_path ?? '').trim();
    const rootChanged = affectedWorkspaces.has('');
    const workspaceChanged = affectedWorkspaces.has(workspace);
    const isAffected = forceFullExtraction || workspaceChanged || (rootChanged && workspace !== '');

    if (isAffected && row.sync_frequency === 'on_commit' && extractionCount < MAX_EXTRACTION_PER_PUSH) {
      try {
        const branchName = ref.startsWith('refs/heads/') ? ref.slice('refs/heads/'.length) : ref;
        const commits = payload.commits ?? [];
        const commitForAfter = commits.find((c: any) => (c.id || c.sha) === after);
        const meta = {
          trigger_type: 'webhook' as const,
          commit_sha: after,
          branch: branchName,
          commit_message: commitForAfter ? (commitForAfter.message || '').slice(0, 500) : undefined,
          commit_author: commitForAfter?.author
            ? {
                username: commitForAfter.author.username ?? commitForAfter.author.name,
                avatar_url: commitForAfter.author.avatar_url,
              }
            : undefined,
        };
        const repoRecord = {
          repo_full_name: row.repo_full_name ?? repoFullName,
          installation_id: '',
          default_branch: row.default_branch,
          package_json_path: row.package_json_path ?? '',
          ecosystem: row.ecosystem ?? 'npm',
          provider: 'gitlab',
          integration_id: row.integration_id ?? undefined,
        };
        const result = await queueExtractionJob(row.project_id, orgId, repoRecord, meta);
        if (result.success) extractionCount++;
      } catch (err: any) {
        console.error(`[gitlab-webhook] Extraction queue failed for ${row.project_id}:`, err?.message);
      }
    }

    const anyFileInWorkspace = changedFiles.some(f => isFileInWorkspace(f, workspace));
    if (anyFileInWorkspace && !isAffected) {
      await queueASTParsingJob(row.project_id, {
        repo_full_name: repoFullName,
        installation_id: '',
        default_branch: row.default_branch,
        package_json_path: workspace,
      }).catch(() => {});
    }

    // Record commits
    const commits = payload.commits ?? [];
    for (const c of commits) {
      const commitSha = c.id || c.sha;
      if (!commitSha) continue;
      await supabase.from('project_commits').upsert({
        project_id: row.project_id,
        sha: commitSha,
        message: (c.message || '').slice(0, 10000),
        author_name: c.author?.name,
        author_email: c.author?.email,
        committed_at: c.timestamp,
        manifest_changed: isAffected,
        extraction_triggered: isAffected && row.sync_frequency === 'on_commit',
        files_changed: (c.added?.length ?? 0) + (c.modified?.length ?? 0) + (c.removed?.length ?? 0),
        provider: 'gitlab',
        provider_url: c.url,
      }, { onConflict: 'project_id,sha' }).then(() => {}).catch(() => {});
    }

    await supabase.from('project_repositories').update({
      last_webhook_at: new Date().toISOString(),
      last_webhook_event: 'push',
      webhook_status: 'active',
    }).eq('project_id', row.project_id).eq('provider', 'gitlab');

    await invalidateProjectCaches(orgId, row.project_id).catch(() => {});
  }
}

// ─── Shared helpers for PR check analysis ─────────────────────────────────────

function getDirectDepsFromPackageJson(pkg: {
  dependencies?: Record<string, string>;
  devDependencies?: Record<string, string>;
}): Record<string, string> {
  const out: Record<string, string> = {};
  for (const [name, spec] of Object.entries(pkg.dependencies || {})) out[name] = spec;
  for (const [name, spec] of Object.entries(pkg.devDependencies || {})) {
    if (!(name in out)) out[name] = spec;
  }
  return out;
}

async function getLicenseForPackage(name: string): Promise<string | null> {
  const { data } = await supabase.from('dependencies').select('license').eq('name', name).single() as { data: { license: string | null } | null };
  if (data?.license) return data.license;
  try {
    const res = await fetch(`https://registry.npmjs.org/${encodeURIComponent(name)}`, {
      headers: { Accept: 'application/json', 'User-Agent': 'Deptex-App' },
    });
    if (!res.ok) return null;
    const data2 = (await res.json()) as { license?: string | { type?: string } };
    if (typeof data2?.license === 'string') return data2.license;
    if (data2?.license?.type) return data2.license.type;
    return null;
  } catch { return null; }
}

const fmtVuln = (v: VulnCounts) =>
  [v.critical_vulns, v.high_vulns, v.medium_vulns, v.low_vulns].some(n => n > 0)
    ? `${v.critical_vulns} critical, ${v.high_vulns} high, ${v.medium_vulns} medium, ${v.low_vulns} low vulnerabilities`
    : '0 vulnerabilities';

// ─── Merge Request Event Handler ──────────────────────────────────────────────

async function handleGitLabMergeRequestEvent(payload: any): Promise<void> {
  const repoFullName = payload?.project?.path_with_namespace;
  const mr = payload?.object_attributes;
  const action = mr?.action;
  const gitlabProjectId = payload?.project?.id;

  if (!repoFullName || !mr) return;

  const mrIid = mr.iid;
  const baseSha = mr.diff_refs?.base_sha || mr.target?.sha;
  const headSha = mr.diff_refs?.head_sha || mr.source?.sha || mr.last_commit?.id;
  const targetBranch = mr.target_branch;

  const { data: projectRows } = await supabase
    .from('project_repositories')
    .select('project_id, default_branch, package_json_path, pull_request_comments_enabled, projects(name, organization_id)')
    .eq('repo_full_name', repoFullName)
    .eq('provider', 'gitlab');

  if (!projectRows?.length) return;

  const matchingProjects = (projectRows as any[]).filter(r => r.default_branch === targetBranch);
  if (matchingProjects.length === 0) return;

  if (action === 'merge') {
    for (const row of matchingProjects) {
      await supabase.from('project_pull_requests').upsert({
        project_id: row.project_id,
        pr_number: mrIid,
        title: mr.title,
        author_login: mr.author?.username || payload?.user?.username,
        status: 'merged',
        provider: 'gitlab',
        provider_url: mr.url,
        base_branch: targetBranch,
        head_branch: mr.source_branch,
        head_sha: headSha,
        merged_at: mr.updated_at || new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }, { onConflict: 'project_id,pr_number,provider' });

      await supabase.from('project_security_fixes')
        .update({ status: 'merged', completed_at: new Date().toISOString() })
        .eq('project_id', row.project_id)
        .eq('pr_number', mrIid)
        .eq('pr_provider', 'gitlab')
        .in('status', ['completed']);

      try {
        const { updateOutcomeOnMerge } = await import('../lib/learning/outcome-recorder');
        await updateOutcomeOnMerge(row.project_id, mrIid, 'gitlab', true, mr.updated_at);
      } catch { /* non-fatal */ }
    }
    return;
  }

  if (action === 'close') {
    for (const row of matchingProjects) {
      await supabase.from('project_pull_requests').upsert({
        project_id: row.project_id,
        pr_number: mrIid,
        title: mr.title,
        author_login: mr.author?.username || payload?.user?.username,
        status: 'closed',
        provider: 'gitlab',
        provider_url: mr.url,
        base_branch: targetBranch,
        head_branch: mr.source_branch,
        head_sha: headSha,
        closed_at: mr.updated_at || new Date().toISOString(),
        updated_at: new Date().toISOString(),
      }, { onConflict: 'project_id,pr_number,provider' });

      await supabase.from('project_security_fixes')
        .update({ status: 'pr_closed', completed_at: new Date().toISOString() })
        .eq('project_id', row.project_id)
        .eq('pr_number', mrIid)
        .eq('pr_provider', 'gitlab')
        .in('status', ['completed']);

      try {
        const { updateOutcomeOnMerge } = await import('../lib/learning/outcome-recorder');
        await updateOutcomeOnMerge(row.project_id, mrIid, 'gitlab', false);
      } catch { /* non-fatal */ }
    }
    return;
  }

  if (!['open', 'update', 'reopen'].includes(action)) return;

  const auth = await getGitLabOAuthToken(repoFullName);
  if (!auth) return;

  let changedFiles: string[] = [];
  try {
    const mrChangesRes = await fetch(
      `https://gitlab.com/api/v4/projects/${gitlabProjectId}/merge_requests/${mrIid}/changes`,
      { headers: { Authorization: `Bearer ${auth.token}`, 'User-Agent': 'Deptex-App' } }
    );
    if (mrChangesRes.ok) {
      const mrChanges = (await mrChangesRes.json()) as { changes?: Array<{ new_path: string; old_path: string }> };
      for (const c of mrChanges.changes ?? []) {
        if (c.new_path) changedFiles.push(c.new_path);
        if (c.old_path && c.old_path !== c.new_path) changedFiles.push(c.old_path);
      }
    }
  } catch {}

  const affectedWorkspaces = detectAffectedWorkspaces(changedFiles);

  for (const row of matchingProjects) {
    const orgId = Array.isArray(row.projects) ? row.projects[0]?.organization_id : row.projects?.organization_id;
    const projectId = row.project_id;
    const projectName = row.projects?.name || 'Project';
    if (!orgId) continue;

    const workspace = (row.package_json_path ?? '').trim();
    const isAffected = affectedWorkspaces.has(workspace) || affectedWorkspaces.has('');

    const checkName = `Deptex - ${projectName}`;

    await createGitLabCommitStatus(auth.token, gitlabProjectId, headSha, 'running', checkName, 'Analyzing dependencies...');

    let blocked = false;
    const blockedBy: Record<string, number> = {};
    const lines: string[] = [`### ${projectName}`, ''];
    let depsAdded = 0;
    let depsUpdated = 0;
    let depsRemoved = 0;

    if (!isAffected) {
      lines.push('No dependency changes detected.');
    } else {
      const ecosystems = affectedWorkspaces.get(workspace) ?? affectedWorkspaces.get('');

      if (ecosystems?.has('npm')) {
        // Deep npm analysis: fetch package.json from base and head refs
        const pkgPath = workspace ? `${workspace}/package.json` : 'package.json';

        let basePkg: Record<string, string> = {};
        let headPkg: Record<string, string> = {};

        try {
          const headContent = await getGitLabFileContent(auth.token, gitlabProjectId, pkgPath, headSha);
          if (headContent) headPkg = getDirectDepsFromPackageJson(JSON.parse(headContent));
        } catch {}
        try {
          const baseContent = await getGitLabFileContent(auth.token, gitlabProjectId, pkgPath, baseSha);
          if (baseContent) basePkg = getDirectDepsFromPackageJson(JSON.parse(baseContent));
        } catch {}

        const directAddedPkgs: Array<{ name: string; version: string }> = [];
        const directBumpedPkgs: Array<{ name: string; oldVersion: string; newVersion: string }> = [];

        for (const [name, spec] of Object.entries(headPkg)) {
          if (!(name in basePkg)) {
            directAddedPkgs.push({ name, version: spec.replace(/[\^~>=<]/g, '') });
          } else if (basePkg[name] !== spec) {
            directBumpedPkgs.push({ name, oldVersion: basePkg[name].replace(/[\^~>=<]/g, ''), newVersion: spec.replace(/[\^~>=<]/g, '') });
          }
        }
        for (const name of Object.keys(basePkg)) {
          if (!(name in headPkg)) depsRemoved++;
        }

        const { acceptedLicenses } = await getEffectivePolicies(orgId, projectId);

        // Load guardrails
        const { data: guardrailsRow } = await supabase.from('project_pr_guardrails').select('*').eq('project_id', projectId).single();
        const guardrails = guardrailsRow as any;
        const hasVulnBlocking = guardrails?.block_critical_vulns || guardrails?.block_high_vulns || guardrails?.block_medium_vulns || guardrails?.block_low_vulns;

        const checkPackage = async (name: string, version: string) => {
          const vulnCounts = await getVulnCountsForPackageVersion(supabase, name, version);
          const license = await getLicenseForPackage(name);
          const policyViolation = Boolean(guardrails?.block_policy_violations && acceptedLicenses.length > 0 && isLicenseAllowed(license, acceptedLicenses) === false);

          if (policyViolation) { blocked = true; blockedBy.policy_violations = (blockedBy.policy_violations ?? 0) + 1; }
          if (hasVulnBlocking) {
            if (guardrails?.block_critical_vulns && exceedsThreshold(vulnCounts, 'critical')) { blocked = true; blockedBy.critical_vulns = (blockedBy.critical_vulns ?? 0) + vulnCounts.critical_vulns; }
            if (guardrails?.block_high_vulns && exceedsThreshold(vulnCounts, 'high')) { blocked = true; blockedBy.high_vulns = (blockedBy.high_vulns ?? 0) + vulnCounts.high_vulns; }
            if (guardrails?.block_medium_vulns && exceedsThreshold(vulnCounts, 'medium')) { blocked = true; blockedBy.medium_vulns = (blockedBy.medium_vulns ?? 0) + vulnCounts.medium_vulns; }
            if (guardrails?.block_low_vulns && exceedsThreshold(vulnCounts, 'low')) { blocked = true; blockedBy.low_vulns = (blockedBy.low_vulns ?? 0) + vulnCounts.low_vulns; }
          }
          return { vulnCounts, license, policyViolation };
        };

        // Load and run PR check code
        let prCheckCode: string | null = null;
        try {
          const { data: proj } = await supabase.from('projects').select('effective_pr_check_code').eq('id', projectId).single();
          prCheckCode = proj?.effective_pr_check_code;
        } catch {}
        if (!prCheckCode) {
          try {
            const { data: orgPrCheck } = await supabase.from('organization_pr_checks').select('pr_check_code').eq('organization_id', orgId).single();
            prCheckCode = orgPrCheck?.pr_check_code;
          } catch {}
        }

        if (prCheckCode?.trim() && (directAddedPkgs.length > 0 || directBumpedPkgs.length > 0)) {
          let projectAssetTier: string | null = null;
          try {
            const { data: projRow } = await supabase.from('projects').select('asset_tier_id').eq('id', projectId).single();
            if (projRow?.asset_tier_id) {
              const { data: tierRow } = await supabase.from('organization_asset_tiers').select('name').eq('id', projRow.asset_tier_id).single();
              if (tierRow?.name) projectAssetTier = tierRow.name;
            }
          } catch {}

          const added = await Promise.all(
            directAddedPkgs.map(async ({ name, version }) => {
              const { policyViolation, vulnCounts, license } = await checkPackage(name, version);
              return {
                name, version, license: license ?? null, is_direct: true,
                policyResult: { allowed: !policyViolation, reasons: policyViolation ? ['Does not comply with project policy'] : [] },
                vulnerability_counts: vulnCounts ? { critical: vulnCounts.critical_vulns, high: vulnCounts.high_vulns, medium: vulnCounts.medium_vulns, low: vulnCounts.low_vulns } : undefined,
              };
            }),
          );
          const updated = await Promise.all(
            directBumpedPkgs.map(async ({ name, oldVersion, newVersion }) => {
              const { policyViolation, vulnCounts, license } = await checkPackage(name, newVersion);
              return {
                name, version: newVersion, oldVersion, license: license ?? null, is_direct: true,
                policyResult: { allowed: !policyViolation, reasons: policyViolation ? ['Does not comply with project policy'] : [] },
                vulnerability_counts: vulnCounts ? { critical: vulnCounts.critical_vulns, high: vulnCounts.high_vulns, medium: vulnCounts.medium_vulns, low: vulnCounts.low_vulns } : undefined,
              };
            }),
          );

          const prContext: Record<string, unknown> = {
            project: { name: projectName, id: projectId, asset_tier: projectAssetTier ?? undefined },
            ecosystem: 'npm',
            changed_files: changedFiles,
            added, updated, removed: [],
            statuses: ['Compliant', 'Non-Compliant'],
          };

          try {
            const prResult = await runPRCheck(prCheckCode, prContext, orgId);
            if (!prResult.passed) {
              blocked = true;
              blockedBy.policy_violations = (blockedBy.policy_violations ?? 0) + 1;
              if (prResult.violations?.length) {
                lines.push('**Policy check:**');
                prResult.violations.forEach((v) => lines.push(`- ${v}`));
                lines.push('');
              }
            }
          } catch (err: any) {
            console.error('[gitlab-pr-check] runPRCheck failed:', err?.message);
            blocked = true;
            blockedBy.policy_violations = (blockedBy.policy_violations ?? 0) + 1;
          }
        }

        if (directBumpedPkgs.length > 0) {
          depsUpdated = directBumpedPkgs.length;
          lines.push('**Packages updated:**');
          for (const { name, oldVersion, newVersion } of directBumpedPkgs.slice(0, 30)) {
            const { vulnCounts } = await checkPackage(name, newVersion);
            lines.push(`- **${name}** \`${oldVersion}\` -> \`${newVersion}\` — ${fmtVuln(vulnCounts)}`);
          }
          lines.push('');
        }

        if (directAddedPkgs.length > 0) {
          depsAdded = directAddedPkgs.length;
          lines.push('**Packages added:**');
          for (const { name, version } of directAddedPkgs.slice(0, 30)) {
            const { vulnCounts, license, policyViolation } = await checkPackage(name, version);
            const policyStr = policyViolation ? ' **(does not comply with project policy)**' : '';
            lines.push(`- **${name}** \`${version}\` — license: ${license ?? 'Unknown'}; ${fmtVuln(vulnCounts)}${policyStr}`);
          }
          lines.push('');
        }

        if (depsRemoved > 0) {
          lines.push(`**${depsRemoved} package(s) removed.**`);
          lines.push('');
        }
      } else {
        // Non-npm ecosystem: shallow analysis
        const changedManifests = changedFiles.filter(f => {
          const fname = f.split('/').pop() || '';
          return ['requirements.txt', 'Pipfile', 'go.mod', 'pom.xml', 'Cargo.toml', 'Gemfile', 'composer.json'].includes(fname);
        });
        if (changedManifests.length > 0) {
          lines.push('**Manifest files changed:**');
          for (const f of changedManifests) lines.push(`- \`${f}\``);
          lines.push('');
          lines.push('*Detailed dependency diff analysis for this ecosystem will be available once full extraction support lands.*');
          lines.push('');
        } else {
          lines.push('Dependency changes detected.');
          lines.push('');
        }
      }
    }

    if (blocked) {
      lines.push('---');
      lines.push('');
      lines.push('**This project cannot be merged until the above issues are resolved.**');
      lines.push('');
    }

    const conclusion = blocked ? 'failed' : 'success';
    const issueCount = Object.values(blockedBy).reduce((a, b) => a + b, 0);
    const summary = blocked
      ? Object.entries(blockedBy).map(([k, v]) => `${v} ${k.replace(/_/g, ' ')}`).join(', ')
      : isAffected ? 'All checked dependencies meet guardrails.' : 'No dependency changes detected.';

    await createGitLabCommitStatus(auth.token, gitlabProjectId, headSha, conclusion, checkName, summary.slice(0, 255));

    await supabase.from('project_pull_requests').upsert({
      project_id: projectId,
      pr_number: mrIid,
      title: mr.title,
      author_login: mr.author?.username || payload?.user?.username,
      status: 'open',
      check_result: blocked ? 'failed' : 'passed',
      check_summary: summary,
      deps_added: depsAdded,
      deps_updated: depsUpdated,
      deps_removed: depsRemoved,
      blocked_by: Object.keys(blockedBy).length > 0 ? blockedBy : null,
      provider: 'gitlab',
      provider_url: mr.url,
      base_branch: targetBranch,
      head_branch: mr.source_branch,
      head_sha: headSha,
      opened_at: mr.created_at,
      last_checked_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
    }, { onConflict: 'project_id,pr_number,provider' });

    if (row.pull_request_comments_enabled !== false) {
      const commentBody = `${DEPTEX_COMMENT_MARKER}\n## Deptex Dependency Check\n\n${lines.join('\n')}\n\n---\n\n*Last updated: ${new Date().toISOString()} UTC*`;
      await findAndEditGitLabMRNote(auth.token, gitlabProjectId, mrIid, commentBody);
    }

    await supabase.from('project_repositories').update({
      last_webhook_at: new Date().toISOString(),
      last_webhook_event: 'merge_request',
      webhook_status: 'active',
    }).eq('project_id', projectId).eq('provider', 'gitlab');
  }
}

router.post('/webhooks/gitlab', async (req: express.Request, res: express.Response) => {
  try {
    const ip = req.ip || req.socket.remoteAddress || 'unknown';
    const rl = await checkRateLimit(`webhook:gitlab:${ip}`, 100, 60);
    if (!rl.allowed) {
      return res.status(429).json({ error: 'Rate limit exceeded' });
    }

    const { valid, repoFullName } = await verifyGitLabWebhookToken(req);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid webhook token' });
    }

    const deliveryId = req.headers['x-gitlab-event-uuid'] as string | undefined;
    const eventType = req.headers['x-gitlab-event'] as string || 'unknown';
    const payloadSize = Buffer.byteLength(JSON.stringify(req.body));

    const startMs = Date.now();
    await recordWebhookDelivery(deliveryId, eventType, req.body?.object_attributes?.action, repoFullName, payloadSize);

    if (await deduplicateDelivery(deliveryId)) {
      await supabase.from('webhook_deliveries').update({ processing_status: 'skipped' })
        .eq('delivery_id', deliveryId || '').eq('provider', 'gitlab');
      return res.json({ received: true, skipped: 'duplicate' });
    }

    res.json({ received: true });

    try {
      if (eventType === 'Push Hook') {
        await handleGitLabPushEvent(req.body);
      } else if (eventType === 'Merge Request Hook') {
        await handleGitLabMergeRequestEvent(req.body);
      }

      const durationMs = Date.now() - startMs;
      await supabase.from('webhook_deliveries').update({
        processing_status: 'processed',
        processing_duration_ms: durationMs,
      }).eq('delivery_id', deliveryId || '').eq('provider', 'gitlab');
    } catch (err: any) {
      console.error('[gitlab-webhook] Processing error:', err?.message);
      await supabase.from('webhook_deliveries').update({
        processing_status: 'error',
        error_message: err?.message?.slice(0, 500),
        processing_duration_ms: Date.now() - startMs,
      }).eq('delivery_id', deliveryId || '').eq('provider', 'gitlab');
    }
  } catch (error: any) {
    console.error('[gitlab-webhook] Error:', error);
    res.status(200).json({ received: true, error: error.message });
  }
});

export default router;
