/**
 * Live probe for the OSV-API fallback. Points it at one of the v3-warm corpus
 * workspace dirs (where dep-scan already wrote sbom-X.cdx.json but no VDR)
 * and prints how many vulnerabilities OSV returned.
 *
 * Usage:
 *   tsx scripts/osv-fallback-probe.ts <reports-dir>
 *
 * Example:
 *   tsx scripts/osv-fallback-probe.ts \
 *     oss-corpus-runs/v3-warm/workspaces/bat/depscan-reports
 *
 * Expected output for bat: 3+ findings (idna, rustix, time crates).
 */

import * as fs from 'node:fs';
import * as path from 'node:path';
import { runOsvFallback } from '../src/pipeline-steps/osv-vuln-scan';

async function main() {
  const reportsDir = process.argv[2];
  if (!reportsDir) {
    console.error('usage: tsx scripts/osv-fallback-probe.ts <reports-dir>');
    process.exit(2);
  }
  if (!fs.existsSync(reportsDir)) {
    console.error(`reports-dir not found: ${reportsDir}`);
    process.exit(2);
  }

  // Infer ecosystem from the SBOM filename — dep-scan names them
  // sbom-<eco>.cdx.json (e.g. sbom-cargo.cdx.json, sbom-maven.cdx.json).
  let eco = 'unknown';
  for (const f of fs.readdirSync(reportsDir)) {
    const m = /^sbom-([a-z0-9]+)\.cdx\.json$/i.exec(f);
    if (m) { eco = m[1]; break; }
  }

  const logger = {
    info: async (step: string, msg: string) => { console.log(`[info ${step}] ${msg}`); },
    warn: async (step: string, msg: string) => { console.warn(`[warn ${step}] ${msg}`); },
    success: async () => {}, error: async () => {},
  };

  console.log(`▶ probing OSV fallback against ${reportsDir} (ecosystem=${eco}, force=true)`);
  const t0 = Date.now();
  const res = await runOsvFallback({
    reportsDir,
    jobEcosystem: eco,
    logger: logger as any,
    force: true,
  });
  const ms = Date.now() - t0;
  console.log(`◀ wrote=${res.wrote} vulnCount=${res.vulnCount} reason=${res.reason ?? '-'} ${ms}ms`);

  const vdrPath = path.join(reportsDir, 'osv-fallback.vdr.json');
  if (fs.existsSync(vdrPath)) {
    const parsed = JSON.parse(fs.readFileSync(vdrPath, 'utf8')) as {
      vulnerabilities: Array<{ id: string; ratings?: Array<{ severity?: string }>; affects?: Array<{ ref?: string }> }>;
    };
    console.log(`\nVulnerabilities (${parsed.vulnerabilities.length}):`);
    for (const v of parsed.vulnerabilities.slice(0, 25)) {
      const sev = v.ratings?.[0]?.severity ?? '?';
      const ref = v.affects?.[0]?.ref ?? '?';
      console.log(`  ${v.id.padEnd(20)} ${sev.padEnd(8)} ${ref}`);
    }
    if (parsed.vulnerabilities.length > 25) {
      console.log(`  ... +${parsed.vulnerabilities.length - 25} more`);
    }
  }
}

main().catch((e) => { console.error(e); process.exit(1); });
