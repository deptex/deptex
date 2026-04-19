import semver from 'semver';

/**
 * OSV-style affected structure (from dependency_vulnerabilities.affected_versions).
 */
type OsvAffected = unknown;

export function isVersionAffected(version: string, affectedVersions: OsvAffected): boolean {
  if (affectedVersions == null) return true;
  const v = semver.valid(semver.coerce(version));
  if (!v) return false;

  const arr = Array.isArray(affectedVersions) ? affectedVersions : [affectedVersions];
  for (const entry of arr) {
    if (entry == null || typeof entry !== 'object') continue;
    const obj = entry as { ranges?: Array<{ events?: Array<{ introduced?: string; fixed?: string }> }>; versions?: string[] };

    if (Array.isArray(obj.versions)) {
      for (const vv of obj.versions) {
        const ev = semver.valid(semver.coerce(vv));
        if (ev && semver.eq(v, ev)) return true;
      }
    }

    const ranges = obj.ranges;
    if (!Array.isArray(ranges)) continue;
    for (const range of ranges) {
      const events = range?.events;
      if (!Array.isArray(events) || events.length === 0) continue;
      let introduced: string | null = null;
      let fixed: string | null = null;
      for (const e of events) {
        if (e?.introduced != null) introduced = String(e.introduced);
        if (e?.fixed != null) fixed = String(e.fixed);
      }
      if (introduced == null) continue;
      const intro = semver.valid(semver.coerce(introduced));
      if (!intro) continue;
      if (semver.lt(v, intro)) continue;
      if (fixed != null) {
        const fix = semver.valid(semver.coerce(fixed));
        if (fix && semver.gte(v, fix)) continue;
      }
      return true;
    }
  }
  return false;
}

export function isVersionFixed(version: string, fixedVersions: string[] | null | undefined): boolean {
  if (!fixedVersions || fixedVersions.length === 0) return false;
  const v = semver.valid(semver.coerce(version));
  if (!v) return false;
  return fixedVersions.some((fv) => {
    const f = semver.valid(semver.coerce(fv));
    return f != null && semver.gte(v, f);
  });
}
