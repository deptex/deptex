/**
 * Per-ecosystem registry fetchers for dependency population.
 * Each fetcher returns a common RegistryInfo shape so populateSingleDependency
 * can work the same way regardless of ecosystem.
 */

export interface RegistryInfo {
  versions: string[];
  weeklyDownloads: number | null;
  github_url: string | null;
  lastPublishedAt: Date | null;
  latest_version: string | null;
  latest_release_date: string | null;
  releasesLast12Months: number;
  description: string | null;
  versionTimestamps: Record<string, string>;
}

const UA = 'Deptex-App/1.0';

function emptyInfo(): RegistryInfo {
  return {
    versions: [],
    weeklyDownloads: null,
    github_url: null,
    lastPublishedAt: null,
    latest_version: null,
    latest_release_date: null,
    releasesLast12Months: 0,
    description: null,
    versionTimestamps: {},
  };
}

function extractGithubUrl(raw: string | undefined | null): string | null {
  if (!raw) return null;
  const m = raw.match(/github\.com[/:]([\w.-]+)\/([\w.-]+?)(?:\.git)?(?:[/#].*)?$/i);
  return m ? `https://github.com/${m[1]}/${m[2]}` : null;
}

function countRecentReleases(timestamps: Record<string, string>): number {
  const cutoff = new Date();
  cutoff.setFullYear(cutoff.getFullYear() - 1);
  let count = 0;
  for (const iso of Object.values(timestamps)) {
    if (new Date(iso) >= cutoff) count++;
  }
  return count;
}

// ---------------------------------------------------------------------------
// PyPI
// ---------------------------------------------------------------------------
async function fetchPypi(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  try {
    const res = await fetch(`https://pypi.org/pypi/${encodeURIComponent(name)}/json`, { headers: { 'User-Agent': UA } });
    if (!res.ok) return info;
    const data = (await res.json()) as any;

    info.description = data.info?.summary ?? null;
    info.latest_version = data.info?.version ?? null;
    info.github_url = extractGithubUrl(data.info?.project_urls?.Source ?? data.info?.project_urls?.Homepage ?? data.info?.home_page);

    const releases = data.releases as Record<string, any[]> | undefined;
    if (releases) {
      const versionNames = Object.keys(releases);
      info.versions = versionNames.reverse().slice(0, 50);
      for (const [ver, files] of Object.entries(releases)) {
        const uploaded = (files as any[])?.[0]?.upload_time_iso_8601;
        if (uploaded) info.versionTimestamps[ver] = uploaded;
      }
      info.releasesLast12Months = countRecentReleases(info.versionTimestamps);
      const latestTs = info.versionTimestamps[info.latest_version ?? ''];
      if (latestTs) {
        info.latest_release_date = latestTs;
        info.lastPublishedAt = new Date(latestTs);
      }
    }

    // PyPI doesn't expose download stats directly; use pypistats if available
    try {
      const dlRes = await fetch(`https://pypistats.org/api/packages/${encodeURIComponent(name)}/recent?period=week`, { headers: { 'User-Agent': UA } });
      if (dlRes.ok) {
        const dlData = (await dlRes.json()) as any;
        info.weeklyDownloads = dlData.data?.last_week ?? null;
      }
    } catch { /* non-fatal */ }
  } catch (e: any) {
    console.warn(`[PyPI] Failed to fetch ${name}:`, e.message);
  }
  return info;
}

// ---------------------------------------------------------------------------
// Maven Central
// ---------------------------------------------------------------------------
function parseMavenCoordinate(name: string): { groupId: string; artifactId: string } | null {
  const parts = name.split(':');
  if (parts.length >= 2) return { groupId: parts[0], artifactId: parts[1] };
  const dotIdx = name.lastIndexOf('.');
  if (dotIdx > 0) return { groupId: name.slice(0, dotIdx), artifactId: name.slice(dotIdx + 1) };
  return null;
}

async function fetchMaven(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  const coords = parseMavenCoordinate(name);
  if (!coords) return info;
  try {
    const q = `g:"${coords.groupId}" AND a:"${coords.artifactId}"`;
    const res = await fetch(`https://search.maven.org/solrsearch/select?q=${encodeURIComponent(q)}&core=gav&rows=50&wt=json`, { headers: { 'User-Agent': UA } });
    if (!res.ok) return info;
    const data = (await res.json()) as any;
    const docs: any[] = data.response?.docs ?? [];

    for (const doc of docs) {
      const v = doc.v as string;
      if (v) {
        info.versions.push(v);
        if (doc.timestamp) {
          info.versionTimestamps[v] = new Date(doc.timestamp).toISOString();
        }
      }
    }

    if (docs.length > 0) {
      info.latest_version = docs[0].v ?? null;
      if (docs[0].timestamp) {
        info.latest_release_date = new Date(docs[0].timestamp).toISOString();
        info.lastPublishedAt = new Date(docs[0].timestamp);
      }
    }

    info.releasesLast12Months = countRecentReleases(info.versionTimestamps);

    // Get project metadata for description and repo URL
    const metaRes = await fetch(`https://search.maven.org/solrsearch/select?q=${encodeURIComponent(q)}&rows=1&wt=json`, { headers: { 'User-Agent': UA } });
    if (metaRes.ok) {
      const metaData = (await metaRes.json()) as any;
      const doc = metaData.response?.docs?.[0];
      if (doc) {
        info.github_url = extractGithubUrl(doc.repositoryUrl ?? null);
      }
    }
  } catch (e: any) {
    console.warn(`[Maven] Failed to fetch ${name}:`, e.message);
  }
  return info;
}

// ---------------------------------------------------------------------------
// NuGet
// ---------------------------------------------------------------------------
async function fetchNuget(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  try {
    const regRes = await fetch(`https://api.nuget.org/v3/registration5-semver1/${encodeURIComponent(name.toLowerCase())}/index.json`, { headers: { 'User-Agent': UA } });
    if (!regRes.ok) return info;
    const regData = (await regRes.json()) as any;

    const allItems: any[] = [];
    for (const page of regData.items ?? []) {
      if (page.items) {
        allItems.push(...page.items);
      } else if (page['@id']) {
        try {
          const pageRes = await fetch(page['@id'], { headers: { 'User-Agent': UA } });
          if (pageRes.ok) {
            const pageData = (await pageRes.json()) as any;
            if (pageData.items) allItems.push(...pageData.items);
          }
        } catch { /* skip page */ }
      }
    }

    const versions: string[] = [];
    for (const item of allItems) {
      const entry = item.catalogEntry ?? item;
      const v = entry.version as string;
      if (v) {
        versions.push(v);
        if (entry.published) info.versionTimestamps[v] = entry.published;
      }
    }
    info.versions = versions.reverse().slice(0, 50);
    info.releasesLast12Months = countRecentReleases(info.versionTimestamps);

    // Metadata from the latest catalog entry
    const latest = allItems[allItems.length - 1]?.catalogEntry;
    if (latest) {
      info.latest_version = latest.version ?? null;
      info.description = latest.description ?? null;
      info.github_url = extractGithubUrl(latest.projectUrl ?? null);
      if (latest.published) {
        info.latest_release_date = latest.published;
        info.lastPublishedAt = new Date(latest.published);
      }
    }

    // Weekly downloads from NuGet stats
    try {
      const searchRes = await fetch(`https://azuresearch-usnc.nuget.org/query?q=packageid:${encodeURIComponent(name)}&take=1`, { headers: { 'User-Agent': UA } });
      if (searchRes.ok) {
        const searchData = (await searchRes.json()) as any;
        const totalDl = searchData.data?.[0]?.totalDownloads;
        if (typeof totalDl === 'number') {
          // NuGet provides total downloads; approximate weekly as total / 52
          const age = info.lastPublishedAt ? Math.max(1, Math.ceil((Date.now() - new Date(regData.items?.[0]?.items?.[0]?.catalogEntry?.published ?? Date.now()).getTime()) / (7 * 24 * 60 * 60 * 1000))) : 52;
          info.weeklyDownloads = Math.round(totalDl / Math.min(age, 520));
        }
      }
    } catch { /* non-fatal */ }
  } catch (e: any) {
    console.warn(`[NuGet] Failed to fetch ${name}:`, e.message);
  }
  return info;
}

// ---------------------------------------------------------------------------
// Go (pkg.go.dev + proxy.golang.org)
// ---------------------------------------------------------------------------
async function fetchGolang(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  try {
    const listRes = await fetch(`https://proxy.golang.org/${encodeURIComponent(name)}/@v/list`, { headers: { 'User-Agent': UA } });
    if (listRes.ok) {
      const text = await listRes.text();
      info.versions = text.split('\n').map((v) => v.trim()).filter(Boolean).reverse().slice(0, 50);
    }

    if (info.versions.length > 0) {
      info.latest_version = info.versions[0];
      try {
        const infoRes = await fetch(`https://proxy.golang.org/${encodeURIComponent(name)}/@v/${encodeURIComponent(info.latest_version)}.info`, { headers: { 'User-Agent': UA } });
        if (infoRes.ok) {
          const verInfo = (await infoRes.json()) as any;
          if (verInfo.Time) {
            info.latest_release_date = verInfo.Time;
            info.lastPublishedAt = new Date(verInfo.Time);
          }
        }
      } catch { /* non-fatal */ }

      for (const v of info.versions.slice(0, 20)) {
        try {
          const vRes = await fetch(`https://proxy.golang.org/${encodeURIComponent(name)}/@v/${encodeURIComponent(v)}.info`, { headers: { 'User-Agent': UA } });
          if (vRes.ok) {
            const vData = (await vRes.json()) as any;
            if (vData.Time) info.versionTimestamps[v] = vData.Time;
          }
        } catch { /* skip */ }
      }
      info.releasesLast12Months = countRecentReleases(info.versionTimestamps);
    }

    // GitHub URL from module path
    if (name.startsWith('github.com/')) {
      const parts = name.split('/');
      if (parts.length >= 3) {
        info.github_url = `https://github.com/${parts[1]}/${parts[2]}`;
      }
    }

    // pkg.go.dev for description
    try {
      const pkgRes = await fetch(`https://pkg.go.dev/${encodeURIComponent(name)}?tab=doc`, { headers: { 'User-Agent': UA } });
      if (pkgRes.ok) {
        const html = await pkgRes.text();
        const descMatch = html.match(/<meta name="description" content="([^"]+)"/);
        if (descMatch) info.description = descMatch[1];
      }
    } catch { /* non-fatal */ }
  } catch (e: any) {
    console.warn(`[Go] Failed to fetch ${name}:`, e.message);
  }
  return info;
}

// ---------------------------------------------------------------------------
// Cargo (crates.io)
// ---------------------------------------------------------------------------
async function fetchCargo(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  try {
    const res = await fetch(`https://crates.io/api/v1/crates/${encodeURIComponent(name)}`, { headers: { 'User-Agent': UA } });
    if (!res.ok) return info;
    const data = (await res.json()) as any;

    const crate = data.crate;
    if (crate) {
      info.description = crate.description ?? null;
      info.latest_version = crate.max_version ?? crate.newest_version ?? null;
      info.weeklyDownloads = crate.recent_downloads ? Math.round(crate.recent_downloads / 13) : null;
      info.github_url = extractGithubUrl(crate.repository ?? null);
      if (crate.updated_at) {
        info.lastPublishedAt = new Date(crate.updated_at);
        info.latest_release_date = crate.updated_at;
      }
    }

    const versions: any[] = data.versions ?? [];
    for (const v of versions.slice(0, 50)) {
      info.versions.push(v.num);
      if (v.created_at) info.versionTimestamps[v.num] = v.created_at;
    }
    info.releasesLast12Months = countRecentReleases(info.versionTimestamps);
  } catch (e: any) {
    console.warn(`[Cargo] Failed to fetch ${name}:`, e.message);
  }
  return info;
}

// ---------------------------------------------------------------------------
// RubyGems
// ---------------------------------------------------------------------------
async function fetchGem(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  try {
    const res = await fetch(`https://rubygems.org/api/v1/gems/${encodeURIComponent(name)}.json`, { headers: { 'User-Agent': UA } });
    if (!res.ok) return info;
    const data = (await res.json()) as any;

    info.description = data.info ?? null;
    info.latest_version = data.version ?? null;
    info.weeklyDownloads = data.downloads ? Math.round(data.downloads / 52) : null;
    info.github_url = extractGithubUrl(data.source_code_uri ?? data.homepage_uri ?? null);

    // Version list
    try {
      const versRes = await fetch(`https://rubygems.org/api/v1/versions/${encodeURIComponent(name)}.json`, { headers: { 'User-Agent': UA } });
      if (versRes.ok) {
        const versData = (await versRes.json()) as any[];
        for (const v of versData.slice(0, 50)) {
          info.versions.push(v.number);
          if (v.created_at) info.versionTimestamps[v.number] = v.created_at;
        }
        if (versData[0]?.created_at) {
          info.latest_release_date = versData[0].created_at;
          info.lastPublishedAt = new Date(versData[0].created_at);
        }
      }
    } catch { /* non-fatal */ }
    info.releasesLast12Months = countRecentReleases(info.versionTimestamps);
  } catch (e: any) {
    console.warn(`[Gem] Failed to fetch ${name}:`, e.message);
  }
  return info;
}

// ---------------------------------------------------------------------------
// Packagist (PHP / Composer)
// ---------------------------------------------------------------------------
async function fetchComposer(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  try {
    const res = await fetch(`https://repo.packagist.org/p2/${name}.json`, { headers: { 'User-Agent': UA } });
    if (!res.ok) return info;
    const data = (await res.json()) as any;

    const packages = data.packages?.[name] ?? [];
    for (const pkg of (packages as any[]).slice(0, 50)) {
      const v = pkg.version_normalized ?? pkg.version;
      if (v) {
        info.versions.push(v);
        if (pkg.time) info.versionTimestamps[v] = pkg.time;
      }
    }

    if (packages.length > 0) {
      const latest = packages[0];
      info.latest_version = latest.version ?? null;
      info.description = latest.description ?? null;
      info.github_url = extractGithubUrl(latest.source?.url ?? null);
      if (latest.time) {
        info.latest_release_date = latest.time;
        info.lastPublishedAt = new Date(latest.time);
      }
    }
    info.releasesLast12Months = countRecentReleases(info.versionTimestamps);

    // Downloads from packagist API
    try {
      const dlRes = await fetch(`https://packagist.org/packages/${name}/stats.json`, { headers: { 'User-Agent': UA } });
      if (dlRes.ok) {
        const dlData = (await dlRes.json()) as any;
        const daily = dlData.downloads?.daily;
        if (typeof daily === 'number') info.weeklyDownloads = daily * 7;
      }
    } catch { /* non-fatal */ }
  } catch (e: any) {
    console.warn(`[Composer] Failed to fetch ${name}:`, e.message);
  }
  return info;
}

// ---------------------------------------------------------------------------
// pub.dev (Dart/Flutter)
// ---------------------------------------------------------------------------
async function fetchPub(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  try {
    const res = await fetch(`https://pub.dev/api/packages/${encodeURIComponent(name)}`, { headers: { 'User-Agent': UA } });
    if (!res.ok) return info;
    const data = (await res.json()) as any;

    const latest = data.latest?.pubspec;
    if (latest) {
      info.description = latest.description ?? null;
      info.latest_version = latest.version ?? null;
      info.github_url = extractGithubUrl(latest.repository ?? latest.homepage ?? null);
    }

    const versions: any[] = data.versions ?? [];
    for (const v of versions.reverse().slice(0, 50)) {
      const ver = v.version ?? v.pubspec?.version;
      if (ver) {
        info.versions.push(ver);
        if (v.published) info.versionTimestamps[ver] = v.published;
      }
    }
    info.releasesLast12Months = countRecentReleases(info.versionTimestamps);

    if (info.versions.length > 0 && info.versionTimestamps[info.versions[0]]) {
      info.latest_release_date = info.versionTimestamps[info.versions[0]];
      info.lastPublishedAt = new Date(info.versionTimestamps[info.versions[0]]);
    }

    // pub.dev score includes popularity (0-100), use as rough weekly proxy
    try {
      const scoreRes = await fetch(`https://pub.dev/api/packages/${encodeURIComponent(name)}/score`, { headers: { 'User-Agent': UA } });
      if (scoreRes.ok) {
        const scoreData = (await scoreRes.json()) as any;
        if (typeof scoreData.popularityScore === 'number') {
          info.weeklyDownloads = Math.round(scoreData.popularityScore * 1000);
        }
      }
    } catch { /* non-fatal */ }
  } catch (e: any) {
    console.warn(`[Pub] Failed to fetch ${name}:`, e.message);
  }
  return info;
}

// ---------------------------------------------------------------------------
// Hex (Elixir)
// ---------------------------------------------------------------------------
async function fetchHex(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  try {
    const res = await fetch(`https://hex.pm/api/packages/${encodeURIComponent(name)}`, { headers: { 'User-Agent': UA } });
    if (!res.ok) return info;
    const data = (await res.json()) as any;

    info.description = data.meta?.description ?? null;
    info.github_url = extractGithubUrl(data.meta?.links?.GitHub ?? data.meta?.links?.github ?? null);
    info.weeklyDownloads = data.downloads?.week ?? null;

    const releases: any[] = data.releases ?? [];
    for (const r of releases.slice(0, 50)) {
      info.versions.push(r.version);
      if (r.inserted_at) info.versionTimestamps[r.version] = r.inserted_at;
    }
    info.releasesLast12Months = countRecentReleases(info.versionTimestamps);

    if (releases.length > 0) {
      info.latest_version = releases[0].version ?? null;
      if (releases[0].inserted_at) {
        info.latest_release_date = releases[0].inserted_at;
        info.lastPublishedAt = new Date(releases[0].inserted_at);
      }
    }
  } catch (e: any) {
    console.warn(`[Hex] Failed to fetch ${name}:`, e.message);
  }
  return info;
}

// ---------------------------------------------------------------------------
// Swift (best-effort via GitHub tags -- no central registry API)
// ---------------------------------------------------------------------------
async function fetchSwift(name: string): Promise<RegistryInfo> {
  const info = emptyInfo();
  // Swift packages typically use GitHub URLs as identifiers
  const ghUrl = extractGithubUrl(name);
  if (ghUrl) {
    info.github_url = ghUrl;
    info.description = `Swift package: ${name}`;
  }
  return info;
}

// ---------------------------------------------------------------------------
// Dispatcher
// ---------------------------------------------------------------------------

const FETCHERS: Record<string, (name: string) => Promise<RegistryInfo>> = {
  pypi: fetchPypi,
  maven: fetchMaven,
  nuget: fetchNuget,
  golang: fetchGolang,
  cargo: fetchCargo,
  gem: fetchGem,
  composer: fetchComposer,
  pub: fetchPub,
  hex: fetchHex,
  swift: fetchSwift,
};

/**
 * Fetch registry info for any supported ecosystem (except npm, which uses the
 * existing fetchNpmPackageInfo in workers.ts).
 * Returns null if the ecosystem has no fetcher (caller should fall back to npm).
 */
export async function fetchRegistryInfo(
  ecosystem: string,
  name: string
): Promise<RegistryInfo | null> {
  const fetcher = FETCHERS[ecosystem];
  if (!fetcher) return null;
  return fetcher(name);
}

export function isSupportedEcosystem(ecosystem: string): boolean {
  return ecosystem === 'npm' || ecosystem in FETCHERS;
}
