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
    response = requests.get(target)
    return response.text
`;

const SAFE_2018_18074 = `from flask import Flask, request
import requests

app = Flask(__name__)


@app.route('/proxy')
def proxy():
    response = requests.get('https://api.internal/status')
    return response.text
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
\t"github.com/gin-gonic/gin"
\t"golang.org/x/text/language"
)

func handler(c *gin.Context) {
\taccept := c.GetHeader("Accept-Language")
\ttags, _, _ := language.ParseAcceptLanguage(accept)
\t_ = tags
}

func main() {
\tr := gin.Default()
\tr.GET("/", handler)
\tr.Run(":8080")
}
`;

const SAFE_2022_32149 = `package main

import (
\t"github.com/gin-gonic/gin"
\t"golang.org/x/text/language"
)

var defaultTag = language.MustParse("en-US")

func handler(c *gin.Context) {
\t_ = defaultTag
\tc.String(200, "ok")
}

func main() {
\tr := gin.Default()
\tr.GET("/", handler)
\tr.Run(":8080")
}
`;

/**
 * CVE-2017-7525 — jackson-databind polymorphic deserialization. ObjectMapper.
 * readValue resolves attacker-controlled class names into Java gadget chains
 * IFF `enableDefaultTyping()` (or `@JsonTypeInfo`) is in effect somewhere
 * upstream on the mapper. The FrameworkSpec format has no precondition gate
 * (see jackson.yaml's documented spec-format gap), so the example MUST list
 * BOTH the readValue sink AND the enableDefaultTyping marker — the fp-filter
 * stage downstream prunes flows where no defaultTyping call is reachable.
 *
 * Teaches the model: Jackson CVEs (2017-7525, 2018-7489, 2019-12384,
 * 2019-14439, 2020-9548) all share this shape — Spring controller source
 * (@RequestBody / @RequestParam) -> mapper.readValue, with a config-gate
 * marker sink so the fp-filter has signal.
 */
const CVE_2017_7525: FrameworkSpecJson = {
  framework: 'jackson-databind',
  version: '<2.8.10',
  language: 'java',
  sources: [],
  sinks: [
    {
      pattern: 'ObjectMapper.readValue(*)',
      vuln_class: 'deserialization',
      argument_indices: [0],
      description: 'Jackson ObjectMapper.readValue with untrusted JSON — gadget-chain RCE when defaultTyping is enabled OR @JsonTypeInfo is present on a target class',
    },
    {
      pattern: 'ObjectMapper.enableDefaultTyping(*)',
      vuln_class: 'deserialization',
      argument_indices: [],
      description: 'Jackson ObjectMapper.enableDefaultTyping — config gate that turns readValue into a gadget-chain sink',
    },
  ],
  sanitizers: [],
};

const VULN_2017_7525 = `import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IngestController {
    @PostMapping("/ingest")
    public Object ingest(@RequestBody String body) throws Exception {
        ObjectMapper.enableDefaultTyping();
        return ObjectMapper.readValue(body, Object.class);
    }
}
`;

const SAFE_2017_7525 = `import com.fasterxml.jackson.databind.ObjectMapper;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
public class IngestController {
    private static final String FIXED_JSON = "{\\"status\\":\\"ok\\"}";

    @PostMapping("/ingest")
    public Object ingest(@RequestBody String body) throws Exception {
        return ObjectMapper.readValue(FIXED_JSON, Object.class);
    }
}
`;

/**
 * Note on Log4j (Log4Shell, CVE-2021-44228 family): we do NOT inline a
 * few-shot for the Log4j gadget shape here. The engine's bundled log4j.yaml
 * already owns wildcard-receiver sinks for every Logger level (`*.info(*)`,
 * `*.warn(*)`, etc.); since the CVE-targeted spec is loaded AFTER framework
 * specs (`validate.ts` line ~230) and `matchSinkPattern` returns the FIRST
 * matching sink, ANY model-emitted literal-receiver Log4j sink gets shadowed
 * by the framework spec and never wins attribution. The Gate 2 round-trip
 * therefore reports `pre=0` even though flows DO fire (they fire against the
 * framework spec's pattern, which we don't count).
 *
 * The Log4j gadget shape is taught via the LOG4SHELL_GADGET_PRIMER text in
 * `prompt-builder.ts` instead — the model still learns the shape, just not
 * via a JSON example.
 */

/**
 * CVE-2023-43804 — urllib3 leaks Cookie header on cross-origin redirect when
 * the URL is attacker-controlled. Patch removes Cookie on redirect. Sink:
 * urllib3.request top-level function (2.x) and PoolManager.urlopen.
 *
 * Teaches the model: urllib3 SSRF CVEs (2023-43804, 2023-45803, 2020-26137,
 * 2024-37891) all share this shape — Flask source (request.args.get) -> any
 * urllib3 entry point that consumes a URL argument. The argument_indices
 * differ per entry point: urllib3.request(method, url) has the URL at index 1.
 */
const CVE_2023_43804: FrameworkSpecJson = {
  framework: 'urllib3',
  version: '<1.26.17 || >=2.0.0 <2.0.6',
  language: 'python',
  sources: [],
  sinks: [
    {
      pattern: 'urllib3.request(*)',
      vuln_class: 'ssrf',
      argument_indices: [1],
      description: 'urllib3.request(method, url) — Cookie / Authorization header leak on cross-origin redirect when URL is attacker-controlled',
    },
    {
      pattern: 'PoolManager.urlopen(*)',
      vuln_class: 'ssrf',
      argument_indices: [1],
      description: 'urllib3.PoolManager().urlopen(method, url) — same redirect-leak class',
    },
    {
      pattern: 'PoolManager.request(*)',
      vuln_class: 'ssrf',
      argument_indices: [1],
      description: 'urllib3.PoolManager().request(method, url) — same redirect-leak class',
    },
  ],
  sanitizers: [],
};

const VULN_2023_43804 = `from flask import Flask, request
import urllib3

app = Flask(__name__)


@app.route('/fetch')
def fetch():
    target = request.args.get('url')
    response = urllib3.request('GET', target)
    return response.data
`;

const SAFE_2023_43804 = `from flask import Flask, request
import urllib3

app = Flask(__name__)


@app.route('/fetch')
def fetch():
    response = urllib3.request('GET', 'https://api.internal/status')
    return response.data
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
  example('CVE-2017-7525', 'com.fasterxml.jackson.core:jackson-databind', 'maven', {
    framework_spec: CVE_2017_7525,
    vulnerable_fixture: VULN_2017_7525,
    safe_fixture: SAFE_2017_7525,
    reachability_level: 'confirmed',
    entry_point_class: 'PUBLIC_UNAUTH',
    rationale: 'jackson-databind polymorphic deserialization is exploitable when the ObjectMapper has enableDefaultTyping() (or activateDefaultTyping in 2.10+) called on it, OR when a target class carries @JsonTypeInfo. Vulnerable fixture: Spring @RequestBody String body -> mapper.readValue, with enableDefaultTyping wired on the mapper. Safe fixture: same controller signature but reads a hard-coded literal JSON constant — body is unused, no taint reaches readValue. The spec emits BOTH the readValue sink AND an enableDefaultTyping marker sink so downstream fp-filter has a config-gate signal (the FrameworkSpec format has no native precondition field — see jackson.yaml header). Same shape applies to CVE-2018-7489, CVE-2019-12384, CVE-2019-14439, CVE-2020-9548.',
  }),
  example('CVE-2023-43804', 'urllib3', 'pypi', {
    framework_spec: CVE_2023_43804,
    vulnerable_fixture: VULN_2023_43804,
    safe_fixture: SAFE_2023_43804,
    reachability_level: 'confirmed',
    entry_point_class: 'PUBLIC_UNAUTH',
    rationale: "urllib3 leaks Cookie / Proxy-Authorization on cross-origin redirect when the request URL is attacker-controlled. Sink: any urllib3 entry point that takes a URL — urllib3.request(method, url), PoolManager.urlopen(method, url), PoolManager.request(method, url). The URL is at argument index 1, not 0 (method is index 0). Vulnerable fixture: Flask request.args.get('url') -> http.request('GET', target). Safe fixture: hard-coded internal URL literal. Same shape applies to CVE-2023-45803, CVE-2020-26137, CVE-2024-37891.",
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
