# `depscanner/test-repos/` — Dogfood Corpus

Hand-authored, per-framework test repositories that exercise the full
Deptex create-project + scan + findings flow end-to-end. Each fixture is a
realistic minimal app intentionally seeded with the categories the depscanner
is supposed to detect (vulnerable dependencies w/ reachable + unreachable
paths, IaC misconfigs, container CVEs, secret leaks, SAST findings, malicious
package patterns, DAST-detectable web vulnerabilities).

Verification is driven by a single `.deptex/expected.yaml` per fixture —
not inline source-code annotations — and consumed by `npm run dogfood:check`
from the depscanner root.

## How this corpus differs from the others

Depscanner ships four distinct fixture families, all serving different layers:

| Corpus | Path | Purpose | Run as |
|---|---|---|---|
| **Unit / snapshot fixtures** | `depscanner/fixtures/test-*` | Snapshot the JSON the scanner emits per ecosystem; catches regressions in the pipeline itself. | `npm run test:fixtures` |
| **Per-CVE rule fixtures** | `depscanner/reachability-rules/CVE-*/` | Each pinned CVE has a tiny vulnerable + safe pair to validate that one rule fires correctly. | `npm run test:taint-engine-all` |
| **Dogfood corpus (this one)** | `depscanner/test-repos/<framework>/` | End-to-end *product* validation: real create-project flow, real UI walkthrough, all categories per fixture. | `npm run dogfood:check` |
| **External reachability benchmark** | `depscanner/reachability-corpus/` | Cross-ecosystem ground truth (real OSS repos w/ hand-labelled CVEs) for tracking reachability precision/recall over time. | `npm run test:reachability-corpus` |

> A subset of dogfood fixtures are **standalone copies** of the matching
> `depscanner/fixtures/test-*` directory (e.g. `test-repos/nextjs/` copies
> from `fixtures/test-nextjs-server-action-xss/`). The originals stay
> byte-stable so snapshot tests keep passing; the copies layer on additional
> categories (Dockerfile, k8s.yaml, secrets, container CVEs, DAST cell).
> Each copy records the upstream SHA in `.deptex/SOURCE.md`.

## v1a coverage (current)

12 fixtures spanning every ecosystem we ship:

| # | Fixture | Ecosystem | Origin | Server-side / DAST |
|---|---|---|---|---|
| 1 | `express` | npm | greenfield | yes |
| 2 | `nextjs` | npm | copy of `test-nextjs-server-action-xss` | yes (SSR) |
| 3 | `react` | npm | greenfield | no (pure SPA) |
| 4 | `django` | pypi | copy of `test-django-xss-pypi` | yes |
| 5 | `fastapi` | pypi | copy of `test-fastapi-sqli-pypi` | yes |
| 6 | `flask` | pypi | copy of `test-flask-traversal-pypi` | yes |
| 7 | `spring-boot` | maven | copy of `test-spring-petclinic-maven` | yes |
| 8 | `gin-gonic` | golang | copy of `test-gin-cmdi-go` | yes |
| 9 | `axum` | cargo | copy of `test-rust-axum-traversal` | yes |
| 10 | `rails` | gem | greenfield | yes |
| 11 | `laravel` | composer | copy of `test-laravel-sqli-php` | yes |
| 12 | `aspnet` | nuget | copy of `test-csharp-aspnet-sqli` | yes |

Tracked progress: see `RESULTS.md` in this directory.

## v1b backlog (deferred)

14 sibling framework detectors covered by extraction-only verification, NOT
the full multi-category seed: vue, svelte, @angular/core, create-react-app,
nuxt, quarkus, android, echo, gofiber, actix, rocket, symfony, wordpress,
sinatra, scrapy.

## Per-fixture layout

```
depscanner/test-repos/<framework>/
├── README.md            # what's seeded + why
├── <source files>       # realistic minimal app (unannotated)
└── .deptex/
    ├── expected.yaml    # alias-aware expected findings (sole source of truth)
    ├── SOURCE.md        # upstream taint-engine fixture SHA, or "greenfield"
    ├── deploy.sh        # server-side fixtures only — boots locally for DAST
    └── dast-baseline.har # server-side fixtures only — recorded after first DAST scan
```

## Running the harness

```bash
cd depscanner
# verify ONE fixture against its expected.yaml:
npm run dogfood:check -- --fixture express --project-id <uuid>

# verify ALL fixtures (cross-batch gate used in M2-M5):
npm run dogfood:check
```

The harness queries Supabase directly with the service-role key. See
`bin/dogfood-check.ts` for env requirements.

## Per-fixture walkthrough

See `docs/runbooks/depscanner-dogfood.md` for the end-to-end manual
walkthrough (create project → connect repo → wait for scan → walk UI tabs →
run `dogfood:check`).

## Safety: malicious-package seeds

Historical-malicious package *versions* are almost always unpublished/yanked by
their registry after the incident. Pinning one in a fixture manifest with no
committed lockfile aborts the whole install — the scan then hard-fails, and the
package can never be enumerated into the dependency tree to be flagged anyway.
The dogfood fixtures therefore do **not** pin unpublished malicious versions;
malicious-package detection is exercised separately. The repo's
`.github/dependabot.yml` still excludes `depscanner/test-repos/**` so Dependabot
never opens real PRs against the intentionally-vulnerable (but published) seeds.
