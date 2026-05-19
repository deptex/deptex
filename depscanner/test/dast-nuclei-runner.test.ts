/**
 * Nuclei runner tests — JSONL parsing + mapping + ephemeral credential cleanup.
 *
 * Covers:
 *   1. parseNucleiJsonl maps a happy-path result (severity, cve_ids, kev,
 *      cwe→owasp, template_id, epss, cpe).
 *   2. A truncated final line is skipped; earlier lines still parse.
 *   3. A result missing `template-id` is dropped.
 *   4. Empty / zero-byte input yields [].
 *   5. Non-JSON noise lines are skipped.
 *   6. Duplicate raw lines are deduped.
 *   7. The `kev` tag is detected case-insensitively.
 *   8. extracted-results are redacted.
 *   9. runNuclei removes the ephemeral credential dir on the resolve path.
 *  10. runNuclei removes the ephemeral credential dir on the reject path.
 *
 * Run: npx tsx test/dast-nuclei-runner.test.ts
 */

import { EventEmitter } from 'events';
import * as fs from 'fs';
import * as os from 'os';
import { parseNucleiJsonl, mapNucleiResult, runNuclei } from '../src/dast/nuclei-runner';

let failures = 0;
let passed = 0;
function assert(cond: unknown, msg: string): void {
  if (!cond) {
    console.error(`  FAIL: ${msg}`);
    failures++;
  } else {
    console.log(`  ok: ${msg}`);
    passed++;
  }
}

// A realistic Nuclei `-jsonl` result line.
const TOMCAT_RESULT = JSON.stringify({
  'template-id': 'CVE-2017-12615',
  info: {
    name: 'Apache Tomcat - Remote Code Execution',
    severity: 'critical',
    description: 'Apache Tomcat PUT-based RCE',
    tags: ['cve', 'cve2017', 'rce', 'kev', 'tomcat'],
    classification: {
      'cve-id': ['CVE-2017-12615'],
      'cwe-id': ['CWE-434'],
      'epss-score': 0.97,
      cpe: 'cpe:2.3:a:apache:tomcat:*:*:*:*:*:*:*:*',
    },
  },
  type: 'http',
  host: 'https://app.example.com',
  'matched-at': 'https://app.example.com/evil.jsp',
  request: 'PUT /evil.jsp HTTP/1.1\r\nHost: app.example.com\r\n\r\n',
  response: 'HTTP/1.1 201 Created',
  'extracted-results': ['version 9.0.0'],
});

const STRUTS_RESULT = JSON.stringify({
  'template-id': 'CVE-2018-11776',
  info: {
    name: 'Apache Struts OGNL injection',
    severity: 'high',
    tags: 'cve,struts,rce',
    classification: { 'cve-id': ['CVE-2018-11776'], 'cwe-id': ['CWE-20'] },
  },
  type: 'http',
  'matched-at': 'https://app.example.com/action',
  request: 'GET /action HTTP/1.1',
});

function testParsing(): void {
  console.log('\n[1] parseNucleiJsonl — happy path');
  const findings = parseNucleiJsonl(`${TOMCAT_RESULT}\n${STRUTS_RESULT}\n`);
  assert(findings.length === 2, `parses 2 findings (got ${findings.length})`);
  const tomcat = findings[0];
  assert(tomcat.severity === 'critical', `tomcat severity = critical (got ${tomcat.severity})`);
  assert(tomcat.engine === 'nuclei', `tomcat engine = nuclei`);
  assert(tomcat.template_id === 'CVE-2017-12615', `tomcat template_id set`);
  assert(tomcat.rule_id === 'CVE-2017-12615', `tomcat rule_id mirrors template_id`);
  assert(
    JSON.stringify(tomcat.cve_ids) === JSON.stringify(['CVE-2017-12615']),
    `tomcat cve_ids = [CVE-2017-12615] (got ${JSON.stringify(tomcat.cve_ids)})`,
  );
  assert(tomcat.kev === true, `tomcat kev = true (kev tag present)`);
  assert(tomcat.cwe_id === '434', `tomcat cwe_id stripped to 434 (got ${tomcat.cwe_id})`);
  // CWE-434 is not in owaspRefForCwe's coarse map → null (helper reused as-is).
  assert(tomcat.owasp_top10_ref === null, `tomcat owasp ref null for unmapped CWE-434`);
  const xss = mapNucleiResult({
    'template-id': 'x',
    info: { name: 'x', severity: 'high', classification: { 'cwe-id': ['CWE-79'] } },
    'matched-at': 'https://x/',
  });
  assert(xss?.owasp_top10_ref === 'A03:2021', `owasp ref derived for mapped CWE-79 (got ${xss?.owasp_top10_ref})`);
  assert(tomcat.epss_score === 0.97, `tomcat epss_score = 0.97`);
  assert(typeof tomcat.cpe === 'string' && tomcat.cpe.includes('tomcat'), `tomcat cpe set`);
  assert(tomcat.http_method === 'PUT', `tomcat method parsed from request (got ${tomcat.http_method})`);
  assert(tomcat.endpoint_url === 'https://app.example.com/evil.jsp', `tomcat endpoint = matched-at`);

  const struts = findings[1];
  assert(struts.kev === false, `struts kev = false (no kev tag)`);
  assert(struts.http_method === 'GET', `struts method = GET`);
  assert(
    JSON.stringify(struts.cve_ids) === JSON.stringify(['CVE-2018-11776']),
    `struts cve_ids parsed from comma-string tags path independent`,
  );

  console.log('\n[2] truncated final line is skipped');
  const truncated = parseNucleiJsonl(`${TOMCAT_RESULT}\n{"template-id":"CVE-2021-`);
  assert(truncated.length === 1, `truncated tail dropped, 1 finding kept (got ${truncated.length})`);

  console.log('\n[3] result missing template-id is dropped');
  const noId = parseNucleiJsonl(
    `${JSON.stringify({ info: { severity: 'high' }, 'matched-at': 'https://x/' })}\n`,
  );
  assert(noId.length === 0, `result without template-id dropped (got ${noId.length})`);

  console.log('\n[4] empty input yields []');
  assert(parseNucleiJsonl('').length === 0, `empty string → []`);
  assert(parseNucleiJsonl('\n\n  \n').length === 0, `whitespace-only → []`);

  console.log('\n[5] non-JSON noise skipped');
  const noisy = parseNucleiJsonl(`some banner text\n${TOMCAT_RESULT}\n[not an object]\n`);
  assert(noisy.length === 1, `noise lines skipped, 1 finding kept (got ${noisy.length})`);

  console.log('\n[6] duplicate raw lines deduped');
  const dupes = parseNucleiJsonl(`${TOMCAT_RESULT}\n${TOMCAT_RESULT}\n${TOMCAT_RESULT}\n`);
  assert(dupes.length === 1, `3 identical lines → 1 finding (got ${dupes.length})`);

  console.log('\n[7] kev tag detected case-insensitively');
  const kevUpper = mapNucleiResult({
    'template-id': 'CVE-2021-0001',
    info: { name: 'x', severity: 'high', tags: ['CVE', 'KEV'] },
    'matched-at': 'https://x/',
  });
  assert(kevUpper?.kev === true, `uppercase KEV tag detected`);

  console.log('\n[8] extracted-results redacted');
  const withSecret = mapNucleiResult({
    'template-id': 'CVE-2021-0002',
    info: { name: 'x', severity: 'low' },
    'matched-at': 'https://x/',
    'extracted-results': ['Bearer abcdefghijklmnopqrstuvwxyz0123456789'],
  });
  assert(
    !!withSecret?.extracted_values?.[0]?.includes('[REDACTED]'),
    `extracted bearer token redacted (got ${JSON.stringify(withSecret?.extracted_values)})`,
  );
}

// ---------------------------------------------------------------------------
// Fake spawn for runNuclei credential-cleanup tests
// ---------------------------------------------------------------------------

type SpawnMode = { kind: 'close'; stdout: string; code: number } | { kind: 'error' };

function makeFakeSpawn(mode: SpawnMode): any {
  return () => {
    const child: any = new EventEmitter();
    child.pid = 4242;
    child.stdout = new EventEmitter();
    child.stderr = new EventEmitter();
    child.kill = () => true;
    setTimeout(() => {
      if (mode.kind === 'error') {
        child.emit('error', new Error('spawn nuclei ENOENT'));
        return;
      }
      if (mode.stdout) child.stdout.emit('data', Buffer.from(mode.stdout, 'utf-8'));
      child.emit('close', mode.code, null);
    }, 5);
    return child;
  };
}

function countTmpDirs(): number {
  return fs.readdirSync(os.tmpdir()).filter((n) => n.startsWith('dast-nuclei-')).length;
}

const control = {
  onHeartbeat: async () => undefined,
  isCancelled: async () => false,
  pollIntervalMs: 100_000, // never fires within the test
};

async function testCredentialCleanup(): Promise<void> {
  console.log('\n[9] runNuclei removes the credential dir on the resolve path');
  const before9 = countTmpDirs();
  const out = await runNuclei(
    {
      targetUrl: 'https://app.example.com/',
      templatesDir: '/opt/nuclei-templates',
      scanTimeoutMinutes: 5,
      authHeaders: { Authorization: 'Bearer secret-token-value' },
      spawnImpl: makeFakeSpawn({ kind: 'close', stdout: `${TOMCAT_RESULT}\n`, code: 0 }),
    },
    control,
  );
  assert(out.findings.length === 1, `[9] runNuclei returned the parsed finding`);
  assert(countTmpDirs() === before9, `[9] no dast-nuclei-* temp dir leaked on resolve`);

  console.log('\n[10] runNuclei removes the credential dir on the reject path');
  const before10 = countTmpDirs();
  let rejected = false;
  try {
    await runNuclei(
      {
        targetUrl: 'https://app.example.com/',
        templatesDir: '/opt/nuclei-templates',
        scanTimeoutMinutes: 5,
        authHeaders: { Cookie: 'session=secret' },
        spawnImpl: makeFakeSpawn({ kind: 'error' }),
      },
      control,
    );
  } catch {
    rejected = true;
  }
  assert(rejected, `[10] runNuclei rejects when the spawn errors`);
  assert(countTmpDirs() === before10, `[10] no dast-nuclei-* temp dir leaked on reject`);
}

async function main(): Promise<void> {
  const t0 = Date.now();
  console.log('Nuclei runner tests\n');
  testParsing();
  await testCredentialCleanup();
  console.log(
    `\nNuclei runner tests ${failures === 0 ? 'PASSED' : 'FAILED'} in ${Date.now() - t0}ms ` +
      `(${passed} passed, ${failures} failure${failures === 1 ? '' : 's'})`,
  );
  process.exit(failures === 0 ? 0 : 1);
}

main().catch((e) => {
  console.error('Unhandled error:', e);
  process.exit(1);
});
