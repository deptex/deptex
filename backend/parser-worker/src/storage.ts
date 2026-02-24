import { createClient } from '@supabase/supabase-js';
import { Redis } from '@upstash/redis';
import { FileAnalysis } from './parser';

const supabaseUrl = process.env.SUPABASE_URL;
const supabaseServiceKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

if (!supabaseUrl || !supabaseServiceKey) {
  throw new Error('SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY must be set');
}

const supabase = createClient(supabaseUrl, supabaseServiceKey);

/** Invalidate dependencies-tab caches when AST parsing completes (same key format as backend cache.ts). */
async function invalidateProjectCachesAfterAst(organizationId: string, projectId: string): Promise<void> {
  const url = process.env.UPSTASH_REDIS_URL;
  const token = process.env.UPSTASH_REDIS_TOKEN;
  if (!url || !token) return;
  try {
    const redis = new Redis({ url, token });
    await Promise.all([
      redis.del(`import:v1:${organizationId}:${projectId}`),
      redis.del(`deps:v1:${organizationId}:${projectId}`),
    ]);
  } catch (err: any) {
    console.warn('[Cache] Failed to invalidate project caches after AST:', err?.message);
  }
}

export interface PackageImportStats {
  packageName: string;
  filesCount: number;
  functions: Set<string>;
  hasDefaultImport: boolean;
}

/**
 * Store analysis results in the database
 */
export async function storeAnalysisResults(
  projectId: string,
  analysisResults: FileAnalysis[]
): Promise<{ success: boolean; error?: string }> {
  try {
    // Get organization_id for cache invalidation
    const { data: project } = await supabase
      .from('projects')
      .select('organization_id')
      .eq('id', projectId)
      .single();
    const organizationId = (project as any)?.organization_id as string | undefined;

    // Aggregate imports by package name, and track which files import each package
    const packageStats = new Map<string, PackageImportStats>();
    const packageFilePaths = new Map<string, Set<string>>();

    for (const file of analysisResults) {
      for (const importInfo of file.imports) {
        const packageName = importInfo.packageName;
        
        if (!packageStats.has(packageName)) {
          packageStats.set(packageName, {
            packageName,
            filesCount: 0,
            functions: new Set<string>(),
            hasDefaultImport: false,
          });
        }

        const stats = packageStats.get(packageName)!;
        stats.filesCount++;
        
        if (importInfo.isDefaultImport) {
          stats.hasDefaultImport = true;
          if (importInfo.defaultImportName) {
            stats.functions.add(importInfo.defaultImportName);
          }
        }
        
        importInfo.functions.forEach((fn) => stats.functions.add(fn));

        // Track which files import this package
        if (!packageFilePaths.has(packageName)) {
          packageFilePaths.set(packageName, new Set<string>());
        }
        packageFilePaths.get(packageName)!.add(file.filePath);
      }
    }

    // Get all project dependencies for this project
    // Only get DIRECT dependencies - we only want to update files_importing_count for packages
    // that are directly imported in the code, not transitive dependencies
    const { data: projectDependencies, error: depsError } = await supabase
      .from('project_dependencies')
      .select('id, name, is_direct')
      .eq('project_id', projectId)
      .eq('is_direct', true);

    if (depsError) {
      throw new Error(`Failed to fetch project dependencies: ${depsError.message}`);
    }

    if (!projectDependencies || projectDependencies.length === 0) {
      console.log(`No direct project dependencies found for project ${projectId}, skipping import analysis storage`);
      // Still mark AST parsing complete so project status becomes 'ready'
      await supabase
        .from('project_repositories')
        .update({
          ast_parsed_at: new Date().toISOString(),
          status: 'ready',
          updated_at: new Date().toISOString(),
        })
        .eq('project_id', projectId);
      if (organizationId) {
        await invalidateProjectCachesAfterAst(organizationId, projectId);
      }
      return { success: true };
    }

    // Normalize import specifier to root package name (lowercase) for matching lockfile deps.
    // e.g. 'lodash/get' -> 'lodash', '@org/pkg/sub' -> '@org/pkg', 'React' -> 'react'
    const getRootPackageKey = (spec: string): string => {
      const lower = spec.toLowerCase();
      if (lower.startsWith('@')) {
        const parts = lower.split('/');
        return parts.slice(0, 2).join('/');
      }
      return lower.split('/')[0];
    };

    // Map root package name (lowercase) -> project_dependency id for lookup
    const depMap = new Map<string, string>();
    for (const dep of projectDependencies) {
      const key = getRootPackageKey(dep.name);
      depMap.set(key, dep.id);
    }

    // Per depId: distinct file count (a file importing both 'lodash' and 'lodash/get' counts once)
    const depIdToFileCount = new Map<string, Set<string>>();
    const functionInserts: Array<{ project_dependency_id: string; function_name: string }> = [];
    const filePathInserts: Array<{ project_dependency_id: string; file_path: string }> = [];

    for (const [packageName, stats] of packageStats) {
      const depId = depMap.get(getRootPackageKey(packageName));
      
      if (depId) {
        if (!depIdToFileCount.has(depId)) depIdToFileCount.set(depId, new Set());
        const fileSet = depIdToFileCount.get(depId)!;
        const paths = packageFilePaths.get(packageName);
        if (paths) paths.forEach((p) => fileSet.add(p));

        // Prepare function inserts
        for (const functionName of stats.functions) {
          functionInserts.push({
            project_dependency_id: depId,
            function_name: functionName,
          });
        }

        // If there's a default import, add it as a function too
        if (stats.hasDefaultImport) {
          functionInserts.push({
            project_dependency_id: depId,
            function_name: 'default',
          });
        }

        // Prepare file path inserts
        const filePaths = packageFilePaths.get(packageName);
        if (filePaths) {
          for (const filePath of filePaths) {
            filePathInserts.push({
              project_dependency_id: depId,
              file_path: filePath,
            });
          }
        }
      }
    }

    const updates = [...depIdToFileCount.entries()].map(([id, fileSet]) => ({
      id,
      filesCount: fileSet.size,
    }));

    // Batch update files_importing_count
    if (updates.length > 0) {
      for (const update of updates) {
        const { error: updateError } = await supabase
          .from('project_dependencies')
          .update({ files_importing_count: update.filesCount })
          .eq('id', update.id);

        if (updateError) {
          console.error(`Failed to update files_importing_count for dependency ${update.id}:`, updateError);
        }
      }
    }

    // Batch insert functions (using upsert to handle duplicates)
    if (functionInserts.length > 0) {
      // Remove duplicates based on project_dependency_id + function_name
      const uniqueFunctions = new Map<string, { project_dependency_id: string; function_name: string }>();
      for (const func of functionInserts) {
        const key = `${func.project_dependency_id}:${func.function_name}`;
        if (!uniqueFunctions.has(key)) {
          uniqueFunctions.set(key, func);
        }
      }

      const functionsArray = Array.from(uniqueFunctions.values());

      // Insert in batches to avoid payload size limits
      const BATCH_SIZE = 100;
      for (let i = 0; i < functionsArray.length; i += BATCH_SIZE) {
        const batch = functionsArray.slice(i, i + BATCH_SIZE);
        
        const { error: insertError } = await supabase
          .from('project_dependency_functions')
          .upsert(batch, {
            onConflict: 'project_dependency_id,function_name',
          });

        if (insertError) {
          console.error(`Failed to insert functions batch:`, insertError);
          // Continue with other batches
        }
      }
    }

    // Batch insert file paths (using upsert to handle duplicates)
    if (filePathInserts.length > 0) {
      // Remove duplicates based on project_dependency_id + file_path
      const uniqueFilePaths = new Map<string, { project_dependency_id: string; file_path: string }>();
      for (const fp of filePathInserts) {
        const key = `${fp.project_dependency_id}:${fp.file_path}`;
        if (!uniqueFilePaths.has(key)) {
          uniqueFilePaths.set(key, fp);
        }
      }

      const filePathsArray = Array.from(uniqueFilePaths.values());

      // Insert in batches to avoid payload size limits
      const BATCH_SIZE = 100;
      for (let i = 0; i < filePathsArray.length; i += BATCH_SIZE) {
        const batch = filePathsArray.slice(i, i + BATCH_SIZE);

        const { error: insertError } = await supabase
          .from('project_dependency_files')
          .upsert(batch, {
            onConflict: 'project_dependency_id,file_path',
          });

        if (insertError) {
          console.error(`Failed to insert file paths batch:`, insertError);
          // Continue with other batches
        }
      }
    }

    console.log(
      `Stored analysis results: ${updates.length} dependencies updated, ${functionInserts.length} functions stored, ${filePathInserts.length} file paths stored`
    );

    // Mark AST parsing complete so project status can transition to 'ready'
    const { error: repoUpdateError } = await supabase
      .from('project_repositories')
      .update({
        ast_parsed_at: new Date().toISOString(),
        status: 'ready',
        updated_at: new Date().toISOString(),
      })
      .eq('project_id', projectId);

    if (repoUpdateError) {
      console.error('Failed to update project_repositories.ast_parsed_at:', repoUpdateError);
      // Don't fail the whole operation - import data was stored
    }

    if (organizationId) {
      await invalidateProjectCachesAfterAst(organizationId, projectId);
    }

    return { success: true };
  } catch (error: any) {
    console.error('Failed to store analysis results:', error);
    return { success: false, error: error.message };
  }
}
