import { SupabaseClient } from '@supabase/supabase-js';
import { Redis } from '@upstash/redis';
import type { FileAnalysis } from './ast-parser';

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
 * Store AST analysis results in the database.
 * Does NOT update project_repositories status -- the pipeline handles that.
 */
export async function storeAstAnalysisResults(
  supabase: SupabaseClient,
  projectId: string,
  organizationId: string,
  analysisResults: FileAnalysis[]
): Promise<{ success: boolean; error?: string }> {
  try {
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

        if (!packageFilePaths.has(packageName)) {
          packageFilePaths.set(packageName, new Set<string>());
        }
        packageFilePaths.get(packageName)!.add(file.filePath);
      }
    }

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
      await invalidateProjectCachesAfterAst(organizationId, projectId);
      return { success: true };
    }

    const getRootPackageKey = (spec: string): string => {
      const lower = spec.toLowerCase();
      if (lower.startsWith('@')) {
        const parts = lower.split('/');
        return parts.slice(0, 2).join('/');
      }
      return lower.split('/')[0];
    };

    const depMap = new Map<string, string>();
    for (const dep of projectDependencies) {
      const key = getRootPackageKey(dep.name);
      depMap.set(key, dep.id);
    }

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

        for (const functionName of stats.functions) {
          functionInserts.push({
            project_dependency_id: depId,
            function_name: functionName,
          });
        }

        if (stats.hasDefaultImport) {
          functionInserts.push({
            project_dependency_id: depId,
            function_name: 'default',
          });
        }

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

    if (functionInserts.length > 0) {
      const uniqueFunctions = new Map<string, { project_dependency_id: string; function_name: string }>();
      for (const func of functionInserts) {
        const key = `${func.project_dependency_id}:${func.function_name}`;
        if (!uniqueFunctions.has(key)) {
          uniqueFunctions.set(key, func);
        }
      }

      const functionsArray = Array.from(uniqueFunctions.values());

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
        }
      }
    }

    if (filePathInserts.length > 0) {
      const uniqueFilePaths = new Map<string, { project_dependency_id: string; file_path: string }>();
      for (const fp of filePathInserts) {
        const key = `${fp.project_dependency_id}:${fp.file_path}`;
        if (!uniqueFilePaths.has(key)) {
          uniqueFilePaths.set(key, fp);
        }
      }

      const filePathsArray = Array.from(uniqueFilePaths.values());

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
        }
      }
    }

    console.log(
      `Stored analysis results: ${updates.length} dependencies updated, ${functionInserts.length} functions stored, ${filePathInserts.length} file paths stored`
    );

    await invalidateProjectCachesAfterAst(organizationId, projectId);

    return { success: true };
  } catch (error: any) {
    console.error('Failed to store analysis results:', error);
    return { success: false, error: error.message };
  }
}
