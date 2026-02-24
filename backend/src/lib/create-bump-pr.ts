import { supabase } from './supabase';
import {
  createInstallationToken,
  getBranchSha,
  createBranch,
  getRepositoryFileWithSha,
  createOrUpdateFileOnBranch,
  createPullRequest,
  getPullRequest,
  closePullRequest,
  listPullRequestsByHead,
} from './github';

function updatePackageJsonDependency(
  packageJsonStr: string,
  packageName: string,
  targetVersion: string
): { content: string } | { error: string } {
  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(packageJsonStr);
  } catch {
    return { error: 'Invalid package.json' };
  }
  const dep = pkg.dependencies?.[packageName];
  const devDep = pkg.devDependencies?.[packageName];
  const current = dep ?? devDep;
  if (current === undefined) {
    return { error: 'This dependency is transitive; only direct dependencies can be bumped via PR.' };
  }
  const prefix = current.startsWith('^') ? '^' : current.startsWith('~') ? '~' : '';
  const versionToWrite = prefix + targetVersion.replace(/^[\^~]/, '');
  if (dep !== undefined) {
    pkg.dependencies = { ...pkg.dependencies, [packageName]: versionToWrite };
  } else {
    pkg.devDependencies = { ...pkg.devDependencies, [packageName]: versionToWrite };
  }
  return { content: JSON.stringify(pkg, null, 2) };
}

/**
 * Create a bump PR for a project (used by manual bump and internal auto-bump).
 */
export async function createBumpPrForProject(
  organizationId: string,
  projectId: string,
  packageName: string,
  targetVersion: string,
  currentVersion?: string
): Promise<{ pr_url: string; pr_number: number } | { error: string }> {
  const { data: depRow } = await supabase
    .from('dependencies')
    .select('id')
    .eq('name', packageName)
    .limit(1)
    .maybeSingle();
  const dependencyId = (depRow as { id?: string } | null)?.id;
  if (!dependencyId) {
    return { error: 'Package not found in dependencies.' };
  }

  const { data: existingBumpPr } = await supabase
    .from('dependency_prs')
    .select('pr_url, pr_number')
    .eq('project_id', projectId)
    .eq('dependency_id', dependencyId)
    .eq('type', 'bump')
    .eq('target_version', targetVersion)
    .maybeSingle();
  if (existingBumpPr) {
    return {
      pr_url: (existingBumpPr as any).pr_url,
      pr_number: (existingBumpPr as any).pr_number,
    };
  }

  const { data: orgRow } = await supabase
    .from('organizations')
    .select('github_installation_id')
    .eq('id', organizationId)
    .single();
  if (!orgRow?.github_installation_id) {
    return { error: 'Organization has no GitHub App connected.' };
  }

  const { data: repoRow } = await supabase
    .from('project_repositories')
    .select('repo_full_name, default_branch, installation_id, package_json_path')
    .eq('project_id', projectId)
    .maybeSingle();
  if (!repoRow?.repo_full_name || !repoRow?.default_branch) {
    return { error: 'Project has no GitHub repository connected.' };
  }

  const installationId = (repoRow as any).installation_id ?? orgRow.github_installation_id;
  const token = await createInstallationToken(installationId);
  const repoFullName = repoRow.repo_full_name;
  const defaultBranch = repoRow.default_branch;
  const packageJsonDir = (repoRow as { package_json_path?: string }).package_json_path ?? '';
  const packageJsonPath = packageJsonDir ? `${packageJsonDir}/package.json` : 'package.json';

  const { data: oldBumpPrs } = await supabase
    .from('dependency_prs')
    .select('pr_number, target_version')
    .eq('project_id', projectId)
    .eq('dependency_id', dependencyId)
    .eq('type', 'bump')
    .neq('target_version', targetVersion);
  if (oldBumpPrs && Array.isArray(oldBumpPrs)) {
    for (const row of oldBumpPrs) {
      const prNumber = (row as any).pr_number;
      const oldTargetVersion = (row as any).target_version;
      try {
        const prState = await getPullRequest(token, repoFullName, prNumber);
        if (prState.state === 'open') {
          await closePullRequest(token, repoFullName, prNumber);
        }
        // Remove row so versions API only shows the single open bump PR
        await supabase
          .from('dependency_prs')
          .delete()
          .eq('project_id', projectId)
          .eq('dependency_id', dependencyId)
          .eq('type', 'bump')
          .eq('target_version', oldTargetVersion);
      } catch (e) {
        console.warn('Could not close old bump PR:', prNumber, e);
      }
    }
  }

  const fromSha = await getBranchSha(token, repoFullName, defaultBranch);
  let branchName = `deptex/bump-${packageName.replace(/[@/]/g, '-')}-${targetVersion}`;
  let branchCreated = false;

  // Try creating the branch, with retry using a suffixed name if it already exists
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      await createBranch(token, repoFullName, branchName, fromSha);
      branchCreated = true;
      break;
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      if (msg.includes('422') && msg.includes('Reference already exists')) {
        // Check for existing PRs on this branch
        const existingPrs = await listPullRequestsByHead(token, repoFullName, branchName);
        if (existingPrs.length > 0) {
          const pr = existingPrs[0];
          await supabase.from('dependency_prs').upsert(
            {
              project_id: projectId,
              dependency_id: dependencyId,
              type: 'bump',
              target_version: targetVersion,
              pr_url: pr.html_url,
              pr_number: pr.number,
              branch_name: branchName,
            },
            {
              onConflict: 'project_id,dependency_id,type,target_version',
            }
          );
          return { pr_url: pr.html_url, pr_number: pr.number };
        }

        // No PR found — retry with a timestamped suffix on first attempt
        if (attempt === 0) {
          const suffix = Date.now().toString(36);
          branchName = `deptex/bump-${packageName.replace(/[@/]/g, '-')}-${targetVersion}-${suffix}`;
          continue;
        }
        return {
          error:
            'A branch for this bump already exists on GitHub but no open PR was found. Delete the branch on GitHub and try again.',
        };
      }
      throw err;
    }
  }
  if (!branchCreated) {
    return { error: 'Failed to create branch after retries' };
  }

  const { content: currentContent, sha: fileSha } = await getRepositoryFileWithSha(
    token,
    repoFullName,
    packageJsonPath,
    branchName
  );
  const result = updatePackageJsonDependency(currentContent, packageName, targetVersion);
  if ('error' in result) {
    return { error: result.error };
  }

  await createOrUpdateFileOnBranch(
    token,
    repoFullName,
    branchName,
    packageJsonPath,
    result.content,
    `chore(deps): bump ${packageName} to ${targetVersion}`,
    fileSha
  );

  const desc = currentVersion
    ? `Updates \`${packageName}\` from \`${currentVersion}\` to \`${targetVersion}\`.\n\nRun \`npm install\` (or your package manager) to update the lockfile.`
    : `Updates \`${packageName}\` to \`${targetVersion}\`.\n\nRun \`npm install\` (or your package manager) to update the lockfile.`;

  const pr = await createPullRequest(
    token,
    repoFullName,
    defaultBranch,
    branchName,
    `Bump ${packageName} to ${targetVersion}`,
    desc
  );

  await supabase.from('dependency_prs').insert({
    project_id: projectId,
    dependency_id: dependencyId,
    type: 'bump',
    target_version: targetVersion,
    pr_url: pr.html_url,
    pr_number: pr.number,
    branch_name: branchName,
  });

  return { pr_url: pr.html_url, pr_number: pr.number };
}
