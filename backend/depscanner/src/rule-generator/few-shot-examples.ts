/**
 * Hand-ported few-shot library for the cross-file CVE-targeted FrameworkSpec
 * generator (Phase 6.5 / M2 prereq, RAA-3 + RAA-6).
 *
 * Phase 5's tournament-tuned few-shot library was 6 weeks of prompt iteration
 * against Semgrep YAML output; throwing it out and starting fresh is the
 * single biggest risk to recall on day 1 of the FrameworkSpec generator. So
 * we hand-port a representative subset to FrameworkSpec form here and gate
 * future expansion on the few-shot CI round-trip test (PDA-4) — every entry
 * MUST pass the engine's round-trip check before being added.
 *
 * Initial corpus: 4 CVEs covering 3 languages (python, js, go) and 4 vuln
 * classes (deserialization, ssrf, open_redirect, redos). M2b will expand
 * coverage to java, ruby, php, rust, csharp once the round-trip Gate 2
 * machinery (validate.ts) is in place.
 *
 * Each entry:
 *   - `cveId`: passed through to the persistence step's osv_id substitution
 *   - `frameworkSpec`: model-output shape (no osv_id; substituted server-side)
 *   - `vulnerableFixture` / `safeFixture`: minimal repros for round-trip test
 *   - `vulnClassHint` / `entryPointClassHint`: what the model ALSO emits in
 *     the response wrapper alongside framework_spec; surfaced here so the
 *     prompt can render a consistent JSON example block
 *
 * The shape mirrors Phase 5's `FewShotExample` (`few-shot-loader.ts`) so
 * the prompt builder can iterate uniformly.
 */

import type {
  FrameworkSpecJson,
  GeneratedFrameworkSpecPayload,
} from './framework-spec-schema';

export interface FrameworkSpecFewShot {
  cveId: string;
  packageName: string;
  ecosystem: string;
  /** The model-output payload for this CVE (model would emit this verbatim). */
  payload: GeneratedFrameworkSpecPayload;
  /**
   * Approximate LOC across spec + fixtures — used to prefer compact examples
   * when the prompt budget is tight. Mirrors `few-shot-loader.FewShotExample.totalLoc`.
   */
  totalLoc: number;
}

function example(
  cveId: string,
  packageName: string,
  ecosystem: string,
  payload: GeneratedFrameworkSpecPayload,
): FrameworkSpecFewShot {
  const specStr = JSON.stringify(payload.framework_spec, null, 2);
  const totalLoc =
    specStr.split('\n').length +
    payload.vulnerable_fixture.split('\n').length +
    payload.safe_fixture.split('\n').length;
  return { cveId, packageName, ecosystem, payload, totalLoc };
}

/**
 * CVE-2020-14343 — PyYAML's default `yaml.load` resolves arbitrary Python
 * tags. Patch swaps in `SafeLoader`. Sink: yaml.load family. Sources covered
 * by Flask framework spec.
 */
const CVE_2020_14343: FrameworkSpecJson = {
  framework: 'pyyaml',
  version: '<5.4',
  language: 'python',
  sources: [],
  sinks: [
    {
      pattern: 'yaml.load(*)',
      vuln_class: 'deserialization',
      argument_indices: [0],
      description: "PyYAML's unsafe yaml.load — default loader resolves arbitrary Python tags",
    },
    {
      pattern: 'yaml.load_all(*)',
      vuln_class: 'deserialization',
      argument_indices: [0],
      description: 'PyYAML yaml.load_all — same unsafe default loader',
    },
    {
      pattern: 'yaml.full_load(*)',
      vuln_class: 'deserialization',
      argument_indices: [0],
      description: 'PyYAML full_load — pre-5.4 FullLoader edge cases let attackers call arbitrary callables',
    },
  ],
  sanitizers: [],
};

const VULN_2020_14343 = `import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def apply_config():
    raw = request.get_data(as_text=True)
    return yaml.load(raw)
`;

const SAFE_2020_14343 = `import yaml
from flask import Flask, request

app = Flask(__name__)


@app.route("/config", methods=["POST"])
def apply_config():
    raw = request.get_data(as_text=True)
    return yaml.safe_load(raw)
`;

/**
 * CVE-2018-18074 — `requests` Authorization header leaks across cross-origin
 * redirects when the target URL is attacker-controlled. Sink: requests.get
 * family. Source: Flask request.args.
 */
const CVE_2018_18074: FrameworkSpecJson = {
  framework: 'requests',
  version: '<2.20.0',
  language: 'python',
  sources: [],
  sinks: [
    {
      pattern: 'requests.get(*)',
      vuln_class: 'ssrf',
      argument_indices: [0],
      description: 'requests.get with attacker-controlled URL — leaks Authorization on cross-origin redirect',
    },
    {
      pattern: 'requests.post(*)',
      vuln_class: 'ssrf',
      argument_indices: [0],
      description: 'requests.post with attacker-controlled URL — same auth-leak class',
    },
    {
      pattern: 'requests.request(*)',
      vuln_class: 'ssrf',
      argument_indices: [1],
      description: 'requests.request with attacker-controlled URL (arg 1 is the URL)',
    },
  ],
  sanitizers: [],
};

const VULN_2018_18074 = `from flask import Flask, request
import requests

app = Flask(__name__)


@app.route('/proxy')
def proxy():
    target = request.args.get('url')
    return requests.get(target, auth=('admin', 'hunter2')).text
`;

const SAFE_2018_18074 = `from flask import Flask, request
import requests

app = Flask(__name__)


@app.route('/proxy')
def proxy():
    return requests.get('https://api.internal/status', auth=('admin', 'hunter2')).text
`;

/**
 * CVE-2024-29041 — Express `res.redirect` with attacker-controlled location
 * is an open redirect. Patch tightens encoding but app-level fix is to
 * validate or allowlist the target URL.
 */
const CVE_2024_29041: FrameworkSpecJson = {
  framework: 'express',
  version: '>=2.0.0 <4.19.2',
  language: 'js',
  sources: [],
  sinks: [
    {
      pattern: 'res.redirect(*)',
      vuln_class: 'open_redirect',
      argument_indices: [0, 1],
      description: 'Express res.redirect with attacker-controlled location — supports both 1-arg (location) and 2-arg (status, location) forms',
    },
  ],
  sanitizers: [],
};

const VULN_2024_29041 = `const express = require('express');
const app = express();

app.get('/go', (req, res) => {
  const target = req.query.next;
  res.redirect(target);
});
`;

const SAFE_2024_29041 = `const express = require('express');
const app = express();

app.get('/go', (req, res) => {
  res.redirect('/dashboard');
});
`;

/**
 * CVE-2022-32149 — `golang.org/x/text/language` Parse / ParseAcceptLanguage
 * is quadratic on crafted input. Patch caps tag length. Sink: language.Parse
 * family. Source covered by go runner's net/http request spec.
 */
const CVE_2022_32149: FrameworkSpecJson = {
  framework: 'golang.org/x/text',
  version: '<0.3.8',
  language: 'go',
  sources: [],
  sinks: [
    {
      pattern: 'language.ParseAcceptLanguage(*)',
      vuln_class: 'redos',
      argument_indices: [0],
      description: 'golang.org/x/text language.ParseAcceptLanguage — quadratic-time parser on attacker tag',
    },
    {
      pattern: 'language.Parse(*)',
      vuln_class: 'redos',
      argument_indices: [0],
      description: 'golang.org/x/text language.Parse — same quadratic-time parse class',
    },
  ],
  sanitizers: [],
};

const VULN_2022_32149 = `package main

import (
\t"net/http"

\t"golang.org/x/text/language"
)

func handler(w http.ResponseWriter, r *http.Request) {
\taccept := r.Header.Get("Accept-Language")
\ttags, _, _ := language.ParseAcceptLanguage(accept)
\t_ = tags
}

func main() {
\thttp.HandleFunc("/", handler)
\thttp.ListenAndServe(":8080", nil)
}
`;

const SAFE_2022_32149 = `package main

import (
\t"net/http"

\t"golang.org/x/text/language"
)

var defaultTag = language.MustParse("en-US")

func handler(w http.ResponseWriter, r *http.Request) {
\t_ = defaultTag
\tw.Write([]byte("ok"))
}

func main() {
\thttp.HandleFunc("/", handler)
\thttp.ListenAndServe(":8080", nil)
}
`;

export const FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES: readonly FrameworkSpecFewShot[] = [
  example('CVE-2020-14343', 'pyyaml', 'pypi', {
    framework_spec: CVE_2020_14343,
    vulnerable_fixture: VULN_2020_14343,
    safe_fixture: SAFE_2020_14343,
    reachability_level: 'confirmed',
    entry_point_class: 'PUBLIC_UNAUTH',
    rationale: 'pyyaml<5.4 yaml.load resolves arbitrary Python tags. Untrusted Flask request data flows directly into the unsafe loader. Safe fixture switches to yaml.safe_load — same source, different (non-sink) callee, so no flow.',
  }),
  example('CVE-2018-18074', 'requests', 'pypi', {
    framework_spec: CVE_2018_18074,
    vulnerable_fixture: VULN_2018_18074,
    safe_fixture: SAFE_2018_18074,
    reachability_level: 'confirmed',
    entry_point_class: 'PUBLIC_UNAUTH',
    rationale: 'requests<2.20 leaks Authorization header on cross-origin redirect when URL is attacker-controlled. Vulnerable: Flask request.args.get -> requests.get. Safe: hard-coded internal URL, no taint reaches the sink.',
  }),
  example('CVE-2024-29041', 'express', 'npm', {
    framework_spec: CVE_2024_29041,
    vulnerable_fixture: VULN_2024_29041,
    safe_fixture: SAFE_2024_29041,
    reachability_level: 'confirmed',
    entry_point_class: 'PUBLIC_UNAUTH',
    rationale: 'Express res.redirect with attacker-controlled location is an open redirect. Vulnerable: req.query.next -> res.redirect. Safe: hard-coded /dashboard literal.',
  }),
  example('CVE-2022-32149', 'golang.org/x/text', 'gomod', {
    framework_spec: CVE_2022_32149,
    vulnerable_fixture: VULN_2022_32149,
    safe_fixture: SAFE_2022_32149,
    reachability_level: 'confirmed',
    entry_point_class: 'PUBLIC_UNAUTH',
    rationale: 'golang.org/x/text<0.3.8 has quadratic-time language tag parsing — DOS via crafted Accept-Language. Vulnerable: r.Header.Get -> language.ParseAcceptLanguage. Safe: literal "en-US" via MustParse, no taint flow.',
  }),
];

/**
 * Top-K selection mirroring `few-shot-loader.loadFewShotExamples` semantics:
 * prefer matches on the requested ecosystem; fall back across ecosystems
 * when the bucket is too small. Within a bucket, smaller examples first.
 */
export function selectFrameworkSpecFewShots(ecosystem: string, k: number): FrameworkSpecFewShot[] {
  if (k <= 0) return [];
  const eco = ecosystem.trim().toLowerCase();
  const sortedByLoc = (xs: FrameworkSpecFewShot[]): FrameworkSpecFewShot[] =>
    xs.slice().sort((a, b) => a.totalLoc - b.totalLoc);
  const matched = sortedByLoc(
    FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES.filter((e) => e.ecosystem.toLowerCase() === eco),
  );
  if (matched.length >= k) return matched.slice(0, k);
  const others = sortedByLoc(
    FRAMEWORK_SPEC_FEW_SHOT_EXAMPLES.filter((e) => e.ecosystem.toLowerCase() !== eco),
  );
  return [...matched, ...others].slice(0, k);
}
