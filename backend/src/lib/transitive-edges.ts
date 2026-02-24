import type { SupabaseClient } from '@supabase/supabase-js';
import pacote from 'pacote';

/**
 * Resolve direct dependencies for a package version via pacote (npm registry)
 * and upsert dependencies, dependency_versions, and dependency_version_edges.
 * Returns the number of edges inserted.
 */
export async function resolveAndUpsertTransitiveEdges(
  supabase: SupabaseClient,
  parentVersionId: string,
  packageName: string,
  version: string
): Promise<number> {
  try {
    const manifest = await pacote.manifest(`${packageName}@${version}`, {
      fullMetadata: false,
    });

    const deps = manifest.dependencies || {};
    const depEntries = Object.entries(deps);

    if (depEntries.length === 0) {
      return 0;
    }

    const edgesToInsert: Array<{ parent_version_id: string; child_version_id: string }> = [];

    for (const [childName, childRange] of depEntries) {
      let resolvedVersion: string;
      try {
        const childManifest = await pacote.manifest(`${childName}@${childRange}`, {
          fullMetadata: false,
        });
        resolvedVersion = childManifest.version;
      } catch {
        continue;
      }

      const { data: childDep } = await supabase
        .from('dependencies')
        .upsert({ name: childName }, { onConflict: 'name', ignoreDuplicates: true })
        .select('id')
        .single();

      if (!childDep) {
        const { data: existingDep } = await supabase
          .from('dependencies')
          .select('id')
          .eq('name', childName)
          .single();
        if (!existingDep) continue;

        const { data: childDv } = await supabase
          .from('dependency_versions')
          .upsert(
            { dependency_id: (existingDep as any).id, version: resolvedVersion },
            { onConflict: 'dependency_id,version', ignoreDuplicates: true }
          )
          .select('id')
          .single();

        if (childDv) {
          edgesToInsert.push({ parent_version_id: parentVersionId, child_version_id: (childDv as any).id });
        } else {
          const { data: existingDv } = await supabase
            .from('dependency_versions')
            .select('id')
            .eq('dependency_id', (existingDep as any).id)
            .eq('version', resolvedVersion)
            .single();
          if (existingDv) {
            edgesToInsert.push({ parent_version_id: parentVersionId, child_version_id: (existingDv as any).id });
          }
        }
      } else {
        const { data: childDv } = await supabase
          .from('dependency_versions')
          .upsert(
            { dependency_id: (childDep as any).id, version: resolvedVersion },
            { onConflict: 'dependency_id,version', ignoreDuplicates: true }
          )
          .select('id')
          .single();

        if (childDv) {
          edgesToInsert.push({ parent_version_id: parentVersionId, child_version_id: (childDv as any).id });
        } else {
          const { data: existingDv } = await supabase
            .from('dependency_versions')
            .select('id')
            .eq('dependency_id', (childDep as any).id)
            .eq('version', resolvedVersion)
            .single();
          if (existingDv) {
            edgesToInsert.push({ parent_version_id: parentVersionId, child_version_id: (existingDv as any).id });
          }
        }
      }
    }

    if (edgesToInsert.length > 0) {
      await supabase
        .from('dependency_version_edges')
        .upsert(edgesToInsert, { onConflict: 'parent_version_id,child_version_id', ignoreDuplicates: true });
    }

    return edgesToInsert.length;
  } catch (pacoteError: any) {
    console.error(`Pacote error resolving ${packageName}@${version}:`, pacoteError.message);
    return 0;
  }
}
