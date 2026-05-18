// Ad-hoc miner — for each CVE in the always-fail set (from 2026-05-14
// multi-trial), walk every prior iterate report and find the AI-generated
// framework_spec from any historical run where that CVE validated. Used
// to extract bucket-G candidates from runs older than today's session.
const fs = require('fs');
const path = require('path');

const ROOT = path.resolve(__dirname, '..', '..', 'bench-iterate');
const ALWAYS_FAIL = new Set([
  'CVE-2026-40175','CVE-2022-23541','CVE-2017-16137','CVE-2024-28849',
  'CVE-2024-35195','CVE-2020-26137','CVE-2019-10906','CVE-2020-28493',
  'CVE-2021-25287','CVE-2023-30861','CVE-2023-37920','CVE-2024-6345',
  'CVE-2022-22965','CVE-2022-22978','CVE-2023-34053','CVE-2023-44483',
  'CVE-2023-26464','CVE-2017-12626','CVE-2022-32149','CVE-2022-27664',
  'CVE-2023-44487','CVE-2024-45337','CVE-2024-21626','CVE-2022-21698',
  'CVE-2022-23633','CVE-2023-28120','CVE-2024-32465','CVE-2022-23837',
]);

const found = {};
function walk(dir) {
  let ents;
  try { ents = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
  for (const ent of ents) {
    const full = path.join(dir, ent.name);
    if (ent.isDirectory()) walk(full);
    else if (ent.name === 'report.json') {
      let r;
      try { r = JSON.parse(fs.readFileSync(full, 'utf8')); } catch { continue; }
      if (!r.perCve) continue;
      for (const c of r.perCve) {
        if (!ALWAYS_FAIL.has(c.cveId)) continue;
        if (c.status !== 'validated') continue;
        if (!c.frameworkSpec) continue;
        if (!found[c.cveId]) found[c.cveId] = [];
        found[c.cveId].push({ run: full, spec: c.frameworkSpec });
      }
    }
  }
}
walk(ROOT);

const cves = Object.keys(found).sort();
console.log('Of', ALWAYS_FAIL.size, 'always-fail CVEs, found prior passing specs for', cves.length);
for (const cveId of cves) {
  console.log('\n== ' + cveId + ' (' + found[cveId].length + ' prior pass(es)) ==');
  const spec = found[cveId][0].spec;
  console.log('   framework: ' + spec.framework + '/' + spec.language);
  for (const s of (spec.sinks || []).slice(0, 5)) {
    console.log('   sink:', s.pattern, '[' + s.vuln_class + ']', 'argi=' + JSON.stringify(s.argument_indices));
  }
}
