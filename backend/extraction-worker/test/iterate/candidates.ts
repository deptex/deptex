/**
 * Cross-ecosystem CVE eval corpus for the rule-generation iteration harness.
 *
 * 88 CVEs stratified across 5 ecosystems:
 *
 *   npm        34   (original 18 + 16 extended)
 *   pypi       23
 *   maven      16
 *   golang      9
 *   rubygems    6
 *
 * Vuln class mix is deliberate: taint, prototype pollution, ReDoS,
 * deserialization, options-bag-shape, command injection, path traversal,
 * header injection, SSRF, XSS. The original 18 npm-only fixture CVEs from
 * Phase 5d are kept at the top so existing on-disk caches stay valid and
 * the prior 18-CVE baseline can still be reproduced via --limit=18.
 *
 * Selection criteria, all verified against OSV.dev on 2026-04-28:
 *   - OSV has an advisory keyed on the CVE id (or its GHSA alias).
 *   - At least one fix reference resolves to a github.com commit URL — the
 *     diff-targeted patch round-trip in validate.ts requires it. Roughly 13
 *     of an originally-considered 101 CVEs were dropped because their OSV
 *     entries pointed only to security-advisory pages, distro patch URLs,
 *     or go.dev/cl change-list links.
 *   - The upstream repo is public and on github.com (not bitbucket /
 *     jboss-git / gitlab — the patch fetcher only speaks GitHub).
 *
 * The packageVersion in each purl is metadata-only (it goes into the prompt)
 * and need not match a real installed fixture version — any version inside
 * the OSV affected range is fine.
 *
 * To re-validate the corpus after editing: `npm run iterate -- --dry-run`
 * populates test/iterate/cache/<CVE>.json and prints status per CVE; any
 * `no_fix_commit` or `fetch_failed` entries should be replaced or removed.
 */

export interface Candidate {
  cveId: string;
  packageName: string;
  packagePurl: string;
  ecosystem: string;
}

// Original 18-CVE npm corpus from Phase 5d. Kept at top so cache files
// (test/iterate/cache/CVE-*.json) populated during 5e/5f/5g remain valid and
// the prior baseline can still be reproduced via --limit=18.
const ORIGINAL_NPM_CORPUS: Candidate[] = [
  { cveId: 'CVE-2025-62718', packageName: 'axios', packagePurl: 'pkg:npm/axios@0.21.1', ecosystem: 'npm' },
  { cveId: 'CVE-2026-40175', packageName: 'axios', packagePurl: 'pkg:npm/axios@0.21.1', ecosystem: 'npm' },
  { cveId: 'CVE-2026-4800', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.20', ecosystem: 'npm' },
  { cveId: 'CVE-2020-28500', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.20', ecosystem: 'npm' },
  { cveId: 'CVE-2022-23539', packageName: 'jsonwebtoken', packagePurl: 'pkg:npm/jsonwebtoken@8.5.1', ecosystem: 'npm' },
  { cveId: 'CVE-2022-23540', packageName: 'jsonwebtoken', packagePurl: 'pkg:npm/jsonwebtoken@8.5.1', ecosystem: 'npm' },
  { cveId: 'CVE-2022-23541', packageName: 'jsonwebtoken', packagePurl: 'pkg:npm/jsonwebtoken@8.5.1', ecosystem: 'npm' },
  { cveId: 'CVE-2022-3517', packageName: 'minimatch', packagePurl: 'pkg:npm/minimatch@3.0.4', ecosystem: 'npm' },
  { cveId: 'CVE-2024-11831', packageName: 'serialize-javascript', packagePurl: 'pkg:npm/serialize-javascript@6.0.0', ecosystem: 'npm' },
  { cveId: 'CVE-2024-55565', packageName: 'nanoid', packagePurl: 'pkg:npm/nanoid@3.2.0', ecosystem: 'npm' },
  { cveId: 'CVE-2025-13465', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.20', ecosystem: 'npm' },
  { cveId: 'CVE-2025-27152', packageName: 'axios', packagePurl: 'pkg:npm/axios@0.21.1', ecosystem: 'npm' },
  { cveId: 'CVE-2025-64718', packageName: 'js-yaml', packagePurl: 'pkg:npm/js-yaml@4.1.0', ecosystem: 'npm' },
  { cveId: 'CVE-2026-25639', packageName: 'axios', packagePurl: 'pkg:npm/axios@0.21.1', ecosystem: 'npm' },
  { cveId: 'CVE-2026-26996', packageName: 'minimatch', packagePurl: 'pkg:npm/minimatch@3.0.4', ecosystem: 'npm' },
  { cveId: 'CVE-2026-27903', packageName: 'minimatch', packagePurl: 'pkg:npm/minimatch@3.0.4', ecosystem: 'npm' },
  { cveId: 'CVE-2026-27904', packageName: 'minimatch', packagePurl: 'pkg:npm/minimatch@3.0.4', ecosystem: 'npm' },
  { cveId: 'CVE-2026-34043', packageName: 'serialize-javascript', packagePurl: 'pkg:npm/serialize-javascript@6.0.0', ecosystem: 'npm' },
];

// Additional npm CVEs widening coverage of vuln classes (proto pollution,
// template injection, ReDoS, command injection, path traversal).
const EXTENDED_NPM_CORPUS: Candidate[] = [
  { cveId: 'CVE-2021-23337', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.20', ecosystem: 'npm' },
  { cveId: 'CVE-2018-3721', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.4', ecosystem: 'npm' },
  { cveId: 'CVE-2019-10744', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.11', ecosystem: 'npm' },
  { cveId: 'CVE-2020-8203', packageName: 'lodash', packagePurl: 'pkg:npm/lodash@4.17.15', ecosystem: 'npm' },
  { cveId: 'CVE-2017-16137', packageName: 'debug', packagePurl: 'pkg:npm/debug@2.6.8', ecosystem: 'npm' },
  { cveId: 'CVE-2017-16138', packageName: 'mime', packagePurl: 'pkg:npm/mime@1.4.0', ecosystem: 'npm' },
  { cveId: 'CVE-2022-24999', packageName: 'qs', packagePurl: 'pkg:npm/qs@6.5.2', ecosystem: 'npm' },
  { cveId: 'CVE-2022-25883', packageName: 'semver', packagePurl: 'pkg:npm/semver@7.3.7', ecosystem: 'npm' },
  { cveId: 'CVE-2022-46175', packageName: 'json5', packagePurl: 'pkg:npm/json5@2.2.0', ecosystem: 'npm' },
  { cveId: 'CVE-2022-37601', packageName: 'loader-utils', packagePurl: 'pkg:npm/loader-utils@2.0.3', ecosystem: 'npm' },
  { cveId: 'CVE-2020-7720', packageName: 'node-forge', packagePurl: 'pkg:npm/node-forge@0.9.1', ecosystem: 'npm' },
  { cveId: 'CVE-2022-31129', packageName: 'moment', packagePurl: 'pkg:npm/moment@2.29.3', ecosystem: 'npm' },
  { cveId: 'CVE-2023-26115', packageName: 'word-wrap', packagePurl: 'pkg:npm/word-wrap@1.2.3', ecosystem: 'npm' },
  { cveId: 'CVE-2024-21484', packageName: 'jsrsasign', packagePurl: 'pkg:npm/jsrsasign@10.5.27', ecosystem: 'npm' },
  { cveId: 'CVE-2024-28849', packageName: 'follow-redirects', packagePurl: 'pkg:npm/follow-redirects@1.15.4', ecosystem: 'npm' },
  { cveId: 'CVE-2024-29041', packageName: 'express', packagePurl: 'pkg:npm/express@4.18.2', ecosystem: 'npm' },
];

// PyPI corpus — yaml.load, jinja2 template, requests/urllib3 transport, pillow
// image parsing, pyjwt algorithm confusion. Heavy on mature audited packages
// where OSV metadata is reliable.
const PYPI_CORPUS: Candidate[] = [
  { cveId: 'CVE-2020-14343', packageName: 'pyyaml', packagePurl: 'pkg:pypi/pyyaml@5.3.1', ecosystem: 'pypi' },
  { cveId: 'CVE-2017-18342', packageName: 'pyyaml', packagePurl: 'pkg:pypi/pyyaml@3.12', ecosystem: 'pypi' },
  { cveId: 'CVE-2018-18074', packageName: 'requests', packagePurl: 'pkg:pypi/requests@2.18.4', ecosystem: 'pypi' },
  { cveId: 'CVE-2023-32681', packageName: 'requests', packagePurl: 'pkg:pypi/requests@2.30.0', ecosystem: 'pypi' },
  { cveId: 'CVE-2024-35195', packageName: 'requests', packagePurl: 'pkg:pypi/requests@2.31.0', ecosystem: 'pypi' },
  { cveId: 'CVE-2020-26137', packageName: 'urllib3', packagePurl: 'pkg:pypi/urllib3@1.25.8', ecosystem: 'pypi' },
  { cveId: 'CVE-2023-43804', packageName: 'urllib3', packagePurl: 'pkg:pypi/urllib3@2.0.5', ecosystem: 'pypi' },
  { cveId: 'CVE-2023-45803', packageName: 'urllib3', packagePurl: 'pkg:pypi/urllib3@2.0.6', ecosystem: 'pypi' },
  { cveId: 'CVE-2024-37891', packageName: 'urllib3', packagePurl: 'pkg:pypi/urllib3@2.2.1', ecosystem: 'pypi' },
  { cveId: 'CVE-2024-26130', packageName: 'cryptography', packagePurl: 'pkg:pypi/cryptography@42.0.4', ecosystem: 'pypi' },
  { cveId: 'CVE-2023-49083', packageName: 'cryptography', packagePurl: 'pkg:pypi/cryptography@41.0.5', ecosystem: 'pypi' },
  { cveId: 'CVE-2024-22195', packageName: 'jinja2', packagePurl: 'pkg:pypi/jinja2@3.1.2', ecosystem: 'pypi' },
  { cveId: 'CVE-2024-34064', packageName: 'jinja2', packagePurl: 'pkg:pypi/jinja2@3.1.3', ecosystem: 'pypi' },
  { cveId: 'CVE-2019-10906', packageName: 'jinja2', packagePurl: 'pkg:pypi/jinja2@2.10', ecosystem: 'pypi' },
  { cveId: 'CVE-2020-28493', packageName: 'jinja2', packagePurl: 'pkg:pypi/jinja2@2.11.2', ecosystem: 'pypi' },
  { cveId: 'CVE-2022-22817', packageName: 'pillow', packagePurl: 'pkg:pypi/pillow@9.0.0', ecosystem: 'pypi' },
  { cveId: 'CVE-2021-25287', packageName: 'pillow', packagePurl: 'pkg:pypi/pillow@8.1.2', ecosystem: 'pypi' },
  { cveId: 'CVE-2023-30861', packageName: 'flask', packagePurl: 'pkg:pypi/flask@2.2.4', ecosystem: 'pypi' },
  { cveId: 'CVE-2024-3651', packageName: 'idna', packagePurl: 'pkg:pypi/idna@3.6', ecosystem: 'pypi' },
  { cveId: 'CVE-2022-29217', packageName: 'pyjwt', packagePurl: 'pkg:pypi/pyjwt@2.3.0', ecosystem: 'pypi' },
  { cveId: 'CVE-2024-21503', packageName: 'black', packagePurl: 'pkg:pypi/black@23.12.1', ecosystem: 'pypi' },
  { cveId: 'CVE-2023-37920', packageName: 'certifi', packagePurl: 'pkg:pypi/certifi@2023.7.22', ecosystem: 'pypi' },
  { cveId: 'CVE-2024-6345', packageName: 'setuptools', packagePurl: 'pkg:pypi/setuptools@69.5.1', ecosystem: 'pypi' },
];

// Maven corpus — heavy on the headline JVM CVEs (Log4Shell, Spring4Shell,
// Text4Shell), Jackson deserialization gadget chains, and Spring Framework
// query/expression bugs. OSV maps these via groupId:artifactId.
const MAVEN_CORPUS: Candidate[] = [
  { cveId: 'CVE-2021-44228', packageName: 'org.apache.logging.log4j:log4j-core', packagePurl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.14.1', ecosystem: 'maven' },
  { cveId: 'CVE-2021-45046', packageName: 'org.apache.logging.log4j:log4j-core', packagePurl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.15.0', ecosystem: 'maven' },
  { cveId: 'CVE-2021-44832', packageName: 'org.apache.logging.log4j:log4j-core', packagePurl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.16.0', ecosystem: 'maven' },
  { cveId: 'CVE-2017-5645', packageName: 'org.apache.logging.log4j:log4j-core', packagePurl: 'pkg:maven/org.apache.logging.log4j/log4j-core@2.8.1', ecosystem: 'maven' },
  { cveId: 'CVE-2019-12384', packageName: 'com.fasterxml.jackson.core:jackson-databind', packagePurl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.8', ecosystem: 'maven' },
  { cveId: 'CVE-2019-14439', packageName: 'com.fasterxml.jackson.core:jackson-databind', packagePurl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.9', ecosystem: 'maven' },
  { cveId: 'CVE-2020-9548', packageName: 'com.fasterxml.jackson.core:jackson-databind', packagePurl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.10.3', ecosystem: 'maven' },
  { cveId: 'CVE-2017-7525', packageName: 'com.fasterxml.jackson.core:jackson-databind', packagePurl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.8.8', ecosystem: 'maven' },
  { cveId: 'CVE-2018-7489', packageName: 'com.fasterxml.jackson.core:jackson-databind', packagePurl: 'pkg:maven/com.fasterxml.jackson.core/jackson-databind@2.9.4', ecosystem: 'maven' },
  { cveId: 'CVE-2022-42889', packageName: 'org.apache.commons:commons-text', packagePurl: 'pkg:maven/org.apache.commons/commons-text@1.9', ecosystem: 'maven' },
  { cveId: 'CVE-2022-22965', packageName: 'org.springframework:spring-beans', packagePurl: 'pkg:maven/org.springframework/spring-beans@5.3.17', ecosystem: 'maven' },
  { cveId: 'CVE-2022-22978', packageName: 'org.springframework.security:spring-security-web', packagePurl: 'pkg:maven/org.springframework.security/spring-security-web@5.6.3', ecosystem: 'maven' },
  { cveId: 'CVE-2023-34053', packageName: 'org.springframework.boot:spring-boot', packagePurl: 'pkg:maven/org.springframework.boot/spring-boot@3.1.6', ecosystem: 'maven' },
  { cveId: 'CVE-2023-44483', packageName: 'org.apache.santuario:xmlsec', packagePurl: 'pkg:maven/org.apache.santuario/xmlsec@3.0.2', ecosystem: 'maven' },
  { cveId: 'CVE-2023-26464', packageName: 'log4j:log4j', packagePurl: 'pkg:maven/log4j/log4j@1.2.17', ecosystem: 'maven' },
  { cveId: 'CVE-2017-12626', packageName: 'org.apache.poi:poi', packagePurl: 'pkg:maven/org.apache.poi/poi@3.15', ecosystem: 'maven' },
];

// Go corpus — limited to packages whose module path resolves to a public
// github.com repo (golang.org/x/* maps to github.com/golang/*). Smaller than
// other ecosystems because OSV go-ecosystem coverage with github commits
// thins out fast outside the standard library mirrors.
const GO_CORPUS: Candidate[] = [
  { cveId: 'CVE-2022-32149', packageName: 'golang.org/x/text', packagePurl: 'pkg:golang/golang.org/x/text@0.3.7', ecosystem: 'golang' },
  { cveId: 'CVE-2022-27664', packageName: 'golang.org/x/net', packagePurl: 'pkg:golang/golang.org/x/net@0.0.0-20220906165146-f3363e06e74c', ecosystem: 'golang' },
  { cveId: 'CVE-2023-3978', packageName: 'golang.org/x/net', packagePurl: 'pkg:golang/golang.org/x/net@0.10.0', ecosystem: 'golang' },
  { cveId: 'CVE-2023-44487', packageName: 'golang.org/x/net', packagePurl: 'pkg:golang/golang.org/x/net@0.16.0', ecosystem: 'golang' },
  { cveId: 'CVE-2024-45337', packageName: 'golang.org/x/crypto', packagePurl: 'pkg:golang/golang.org/x/crypto@0.30.0', ecosystem: 'golang' },
  { cveId: 'CVE-2024-21626', packageName: 'github.com/opencontainers/runc', packagePurl: 'pkg:golang/github.com/opencontainers/runc@1.1.11', ecosystem: 'golang' },
  { cveId: 'CVE-2024-28180', packageName: 'github.com/go-jose/go-jose/v4', packagePurl: 'pkg:golang/github.com/go-jose/go-jose/v4@4.0.0', ecosystem: 'golang' },
  { cveId: 'CVE-2022-21698', packageName: 'github.com/prometheus/client_golang', packagePurl: 'pkg:golang/github.com/prometheus/client_golang@1.11.0', ecosystem: 'golang' },
  { cveId: 'CVE-2022-29153', packageName: 'github.com/hashicorp/consul', packagePurl: 'pkg:golang/github.com/hashicorp/consul@1.11.4', ecosystem: 'golang' },
];

// RubyGems corpus — Rails CVEs dominate (most public ruby vuln traffic). OSV
// metadata is reliable here since rails/rails fix commits are well-cited.
const RUBYGEMS_CORPUS: Candidate[] = [
  { cveId: 'CVE-2022-23633', packageName: 'actionpack', packagePurl: 'pkg:gem/actionpack@7.0.0', ecosystem: 'rubygems' },
  { cveId: 'CVE-2023-28120', packageName: 'activesupport', packagePurl: 'pkg:gem/activesupport@7.0.4.1', ecosystem: 'rubygems' },
  { cveId: 'CVE-2024-26143', packageName: 'actionpack', packagePurl: 'pkg:gem/actionpack@7.1.3', ecosystem: 'rubygems' },
  { cveId: 'CVE-2024-25126', packageName: 'sinatra', packagePurl: 'pkg:gem/sinatra@3.1.0', ecosystem: 'rubygems' },
  { cveId: 'CVE-2024-32465', packageName: 'git', packagePurl: 'pkg:gem/git@1.19.1', ecosystem: 'rubygems' },
  { cveId: 'CVE-2022-23837', packageName: 'rack', packagePurl: 'pkg:gem/rack@2.2.3', ecosystem: 'rubygems' },
];

export const CANDIDATES: Candidate[] = [
  ...ORIGINAL_NPM_CORPUS,
  ...EXTENDED_NPM_CORPUS,
  ...PYPI_CORPUS,
  ...MAVEN_CORPUS,
  ...GO_CORPUS,
  ...RUBYGEMS_CORPUS,
];

/**
 * Filter the corpus to a single ecosystem. Useful for ecosystem-specific
 * iteration runs without forcing a CLI flag — call from a custom script:
 *
 *   import { candidatesByEcosystem } from './candidates';
 *   const npm = candidatesByEcosystem('npm');
 */
export function candidatesByEcosystem(ecosystem: string): Candidate[] {
  const norm = ecosystem.toLowerCase();
  return CANDIDATES.filter((c) => c.ecosystem.toLowerCase() === norm);
}
