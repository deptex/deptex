import { dynamicTool, jsonSchema } from 'ai';
import { supabase } from '../../supabase';

export function getPackageReputationTool(_ctx: { organizationId: string }) {
  return dynamicTool({
    description:
      'Package reputation data: OpenSSF Scorecard, weekly downloads, last published date, maintenance signals, and whether the package is flagged malicious. Input is the package name as stored (e.g. lodash, express, requests).',
    inputSchema: jsonSchema({
      type: 'object',
      properties: {
        packageName: { type: 'string', minLength: 1, description: 'Package name as stored.' },
      },
      required: ['packageName'],
      additionalProperties: false,
    }),
    execute: async (input) => {
      const { packageName } = input as { packageName: string };

      const { data, error } = await supabase
        .from('dependencies')
        .select(
          'id, name, status, score, openssf_score, openssf_penalty, popularity_penalty, maintenance_penalty, weekly_downloads, last_published_at, releases_last_12_months, github_url, latest_version, latest_release_date, description, is_malicious, license',
        )
        .eq('name', packageName)
        .maybeSingle();

      if (error) return { error: error.message };
      if (!data) return { error: `Package "${packageName}" not found in the Deptex reputation cache.` };

      return {
        name: data.name,
        analysisStatus: data.status,
        reputationScore: data.score,
        openssfScore: data.openssf_score,
        scorePenalties: {
          openssf: data.openssf_penalty ?? 0,
          popularity: data.popularity_penalty ?? 0,
          maintenance: data.maintenance_penalty ?? 0,
        },
        weeklyDownloads: data.weekly_downloads,
        lastPublishedAt: data.last_published_at,
        releasesLast12Months: data.releases_last_12_months,
        githubUrl: data.github_url,
        description: data.description,
        latestVersion: data.latest_version,
        latestReleaseDate: data.latest_release_date,
        license: data.license,
        isMalicious: !!data.is_malicious,
      };
    },
  });
}
