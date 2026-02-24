import { supabase } from './supabase';
import {
  createInstallationToken,
  getBranchSha,
  createBranch,
  getRepositoryFileWithSha,
  createOrUpdateFileOnBranch,
  createPullRequest,
  listPullRequestsByHead,
} from './github';

function removePackageJsonDependency(
  packageJsonStr: string,
  packageName: string
): { content: string } | { error: string } {
  let pkg: { dependencies?: Record<string, string>; devDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(packageJsonStr);
  } catch {
    return { error: 'Invalid package.json' };
  }
  const dep = pkg.dependencies?.[packageName];
  const devDep = pkg.devDependencies?.[packageName];
  if (dep === undefined && devDep === undefined) {
    return { error: 'This dependency was not found in package.json. It may be transitive or already removed.' };
  }
  if (dep !== undefined && pkg.dependencies) {
    const { [packageName]: _, ...rest } = pkg.dependencies;
    pkg.dependencies = rest;
  }
  if (devDep !== undefined && pkg.devDependencies) {
    const { [packageName]: _, ...rest } = pkg.devDependencies;
    pkg.devDependencies = rest;
  }
  return { content: JSON.stringify(pkg, null, 2) };
}

/**
 * Create a PR to remove an unused (zombie) dependency from package.json.
 */
export async function createRemovePrForProject(
  organizationId: string,
  projectId: string,
  packageName: string
): Promise<{ pr_url: string; pr_number: number; already_exists?: boolean } | { error: string }> {
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

  // Check for an existing remove PR for this package
  const { data: existingRemovePr } = await supabase
    .from('dependency_prs')
    .select('pr_url, pr_number')
    .eq('project_id', projectId)
    .eq('dependency_id', dependencyId)
    .eq('type', 'remove')
    .maybeSingle();
  if (existingRemovePr) {
    return {
      pr_url: (existingRemovePr as any).pr_url,
      pr_number: (existingRemovePr as any).pr_number,
      already_exists: true,
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

  const fromSha = await getBranchSha(token, repoFullName, defaultBranch);
  const branchName = `deptex/remove-${packageName.replace(/[@/]/g, '-')}`;

  try {
    await createBranch(token, repoFullName, branchName, fromSha);
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (msg.includes('422') && msg.includes('Reference already exists')) {
      const existingPrs = await listPullRequestsByHead(token, repoFullName, branchName);
      if (existingPrs.length > 0) {
        const pr = existingPrs[0];
        await supabase.from('dependency_prs').upsert(
          {
            project_id: projectId,
            dependency_id: dependencyId,
            type: 'remove',
            target_version: 'remove',
            pr_url: pr.html_url,
            pr_number: pr.number,
            branch_name: branchName,
          },
          {
            onConflict: 'project_id,dependency_id,type,target_version',
          }
        );
        return { pr_url: pr.html_url, pr_number: pr.number, already_exists: true };
      }
      return {
        error:
          'A branch for this removal already exists on GitHub but no open PR was found. Delete the branch on GitHub and try again, or open the existing branch as a PR manually.',
      };
    }
    throw err;
  }

  const { content: currentContent, sha: fileSha } = await getRepositoryFileWithSha(
    token,
    repoFullName,
    packageJsonPath,
    branchName
  );
  const result = removePackageJsonDependency(currentContent, packageName);
  if ('error' in result) {
    return { error: result.error };
  }

  await createOrUpdateFileOnBranch(
    token,
    repoFullName,
    branchName,
    packageJsonPath,
    result.content,
    `chore(deps): remove unused dependency ${packageName}`,
    fileSha
  );

  const desc = `Removes \`${packageName}\` from \`package.json\`.\n\nThis package was detected as unused — it is not imported in any file in the project.\n\nRun \`npm install\` (or your package manager) after merging to update the lockfile.`;

  const pr = await createPullRequest(
    token,
    repoFullName,
    defaultBranch,
    branchName,
    `Remove unused dependency \`${packageName}\``,
    desc
  );

  await supabase.from('dependency_prs').insert({
    project_id: projectId,
    dependency_id: dependencyId,
    type: 'remove',
    target_version: 'remove',
    pr_url: pr.html_url,
    pr_number: pr.number,
    branch_name: branchName,
  });

  return { pr_url: pr.html_url, pr_number: pr.number };
}
