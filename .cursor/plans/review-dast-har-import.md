# Plan Review — dast-har-import (Round 3)

**Verdict: REVISE** (0 P0s — substantially READY; 6 P1s are concentrated plan-citation accuracy fixes + 1 missing test + Patch A privacy tightenings)

Plan reviewed: `.cursor/plans/dast-har-import.plan.md` (post-Patches-A-H, 761 lines)
Generated: 2026-05-21
Mode: lean (7 personas — 6 always-include + 1 forced); debate: off
Personas: skeptic, pragmatist, scope-cutter, architect, test-strategy-auditor, opportunity-scout, **byok-secrets-auditor** (forced)
Vote tally (self-declared): **3 READY / 4 REVISE / 0 REWORK**
Findings: **0 P0 / 6 P1 / 12 P2 / 14 P3** (32 total)

**Trajectory:** Round 1 7P0/19P1 → Round 2 1P0/8P1 → **Round 3 0P0/6P1**. Plan is in good shape — every Round 2 finding was substantively resolved; the new P1s are all concrete, narrow, ~5-10 minutes each to fix.

## Summary

Three of seven personas (`pragmatist`, `test-strategy-auditor`, `opportunity-scout`) self-declared READY. The 4 REVISE votes converge on **three concrete plan-citation correctness issues** (Patches B/D/G have file:line or claim errors that would mislead /implement) + **one missing test** (Patch D extends v2.1d recorded behavior but the recorded-variant regression test is named only in prose, not in M3 step 7b deliverables or hard acceptance criteria) + **two Patch A privacy tightenings** (TOTP secret not in zeroing perimeter; base32 validator regex + script-injection discipline unspecified).

Cross-persona convergences:
- **Patch B body-parser diff is wrong** (`skeptic-r3-f1` + `ARCH-R3-3`): dast router mounted at index.ts:156 AFTER global json at :109; router-internal `express.json` is a no-op.
- **Patch D recorded-variant regression test missing** (`ARCH-R3-1` + `TSA3-1`): file named once in Regression-surface paragraph but absent from M3 step 7b, file inventory, and hard acceptance.
- **Patch G cron fallback ambiguous** (`skeptic-r3-f3` + `byok-r3-NEW-5`): two different remediation paths for same uncertainty.

## Vote Tally

| Persona | Vote | Top concern |
|---|---|---|
| skeptic | REVISE (implied) | skeptic-r3-f1: Patch B body-parser diff broken |
| pragmatist | **READY** | prag-r3-1: M0 step 6 budget tight (P2) |
| scope-cutter | REVISE-with-minor-cuts | SC-13-R3: drop [dast-replay-crypto] (re-cut P2) |
| architect | REVISE (substantively READY modulo 1 P1) | ARCH-R3-1: missing recorded regression test |
| test-strategy-auditor | **READY-with-1-P2** | TSA3-1: same as ARCH-R3-1 |
| opportunity-scout | **READY** | OS-NEW-2-r3: canary helper extraction (P3) |
| byok-secrets-auditor | REVISE | byok-r3-NEW-1: TOTP secret zeroing perimeter |

## P0 — None

No P0 findings. The Round 2 converged TOTP P0 is concretely resolved by Patch A (Decision 18 + RFC 6238 helper + M0 step 6 full re-auth-cycle validation).

## P1 — High-Priority Gaps (6)

### 1. `patch-b-body-parser-diff-broken` `[CONVERGED — skeptic-r3-f1 + ARCH-R3-3]`
- **Plan section:** M2 step 1 (line ~483); Threat Model Step 3 (line ~330)
- **Claim:** Patch B says "mount the dast router with its own 1.5mb express.json BEFORE the global 100kb json middleware" and recommends "the first" option (router-internal express.json). **This doesn't work.** Express middleware fires in mount order. `backend/src/index.ts:109` mounts global `express.json({ limit: '100kb' })`; the dast router mounts at line 156 AFTER. By the time the request reaches dastRouter, the global parser has already populated `req._body=true` and a router-internal express.json no-ops. Round 2 explicitly identified this trap; the patched plan picked the broken option.
- **Suggested patch:** Swap Patch B's recommendation to option 2 (path-gated global): `app.use((req, res, next) => req.path.match(/^\/api\/projects\/[^/]+\/dast\/replay\/preview/) ? next() : express.json({ limit: '100kb' })(req, res, next));` mounted at the existing line 109 site. OR (cleaner if no other route depends on req.body before line 156) move the dast router mount above line 109 with its own 1.5mb parser. M2 step 1 must include the concrete diff sketch so /implement doesn't recreate the silent-fail trap.

### 2. `patch-d-wrong-file-and-threshold` `[SOLO — skeptic-r3-f2]`
- **Plan section:** M3 step 7b (lines ~529-534); dast-replay-session-loss.test.ts spec
- **Claim:** Two grep-verified errors in Patch D's spec:
  - **(a)** Step 7b(a) says "Locate the form-only `consecutive_lost_count` increment site in `pipeline.ts` (grep ... comment at 1661 says it's form-only)." But the actual INCREMENT lives at `depscanner/src/dast/control-plane.ts:276` inside `createAuthLostWatcher` (called from pipeline.ts:721) and is **engine-wide, not form-only**. The form-only thing is the *re-login retry* path, not the counter increment. An implementer following step 7b(a) literally greps in the wrong file.
  - **(b)** Test spec says "two consecutive misses → assert `consecutive_lost_count: 2`." But `pipeline.ts:1816` reads `authLostThresholdHit = ... consecutiveLostCount >= 4`. Two misses won't trip the threshold; the test as written would fail.
- **Suggested patch:** Rewrite M3 step 7b(a): "Locate `consecutive_lost_count` increment in `control-plane.ts:276` (inside `createAuthLostWatcher`). Counter is engine-wide; what's form-only is the *re-login* path. Replay extension = add a re-login firing point for replay strategy AND emit `session_loss` envelope from replay when threshold trips." Rewrite step 7b(d) test fixture: either parameterize watcher threshold to 2 for test config OR simulate 4 misses; assert `consecutive_lost_count: 4` (whatever the threshold actually is).

### 3. `patch-g-cron-circular-reference` `[CONVERGED — skeptic-r3-f3 + byok-r3-NEW-5]`
- **Plan section:** Threat Model Step 6 (line ~344-346); M0 step 0b (line ~422); Risks #6 (line ~698)
- **Claim:** Patch G's Threat Model Step 6 states as a positive guarantee: "row + 256-byte excerpts retained for max 7 days then purged via existing `scan_jobs_retention` cron." Then M0 step 0b says: "Verify `scan_jobs_retention` cron exists; if not, file a follow-up M5 task to create one." Two issues:
  - **Grep-cold:** `scan_jobs_retention` does NOT appear in the codebase. There IS no existing cron with that name.
  - **Circular:** Risks #6 claims "Resolved by Patch G: never on credential row; **test-job row TTL ≤7d on failure**; null on success; role-gated GET." The TTL guarantee depends on a cron that the plan acknowledges may not exist + offloads to a follow-up task (NOT in this PR).
- **Suggested patch:** Pick one: (a) Move "create scan_jobs_retention cron with 7d purge for `dast_zap_dry_run` test rows" from M0 follow-up into a HARD M5 step in THIS PR (concrete: a phase36a migration or backend cron handler). Update Risks #6 to require this. (b) Descope to a stronger guarantee that doesn't require a new cron — worker sets a delayed null-overwrite on the row regardless of success/failure (e.g., 60s after test-job completion). Recommend (a); cron + 7d TTL is the standard pattern.

### 4. `patch-d-recorded-regression-test-missing-from-inventory` `[CONVERGED — ARCH-R3-1 + TSA3-1]`
- **Plan section:** M3 step 7b(d) (line ~533); Regression surface (line ~685); File inventory (lines 53-99); Hard acceptance (lines 733-755)
- **Claim:** Patch D mutates v2.1d recorded behavior (changes the `pre_flight_failed` envelope path to emit `session_loss` on second miss). Line 685 (Regression surface) explicitly promises: "`dast-pipeline-session-loss-recorded.test.ts` (NEW alongside the replay variant) MUST be added in M3 step 7b to pin v2.1d recorded behavior under the new machinery." BUT this file is:
  - NOT in the "Existing files we WILL modify" inventory
  - NOT enumerated inside M3 step 7b(d), which only names `dast-replay-session-loss.test.ts`
  - NOT in Hard Acceptance Criteria #13-18 (#15 cites only the replay variant)
  - NOT in the worker test inventory (lines 656-663)
- The existing `dast-pipeline-auth-state.test.ts` has 3 cases — all on the form path; none exercise the recorded `pre_flight_failed → session_loss` transition. The "0 regression on existing v2.1d test suite" claim is technically true but trivially — there IS no regression gate, only no regression *test*.
- **Suggested patch:** Three coordinated 1-line edits: (a) Add row to file inventory: `depscanner/src/__tests__/dast-pipeline-session-loss-recorded.test.ts (NEW — Patch D recorded regression: two-miss → session_loss for recorded; pins v2.1d behavior under extended machinery)`. (b) Extend M3 step 7b(d): "Tests: `dast-replay-session-loss.test.ts` AND `dast-pipeline-session-loss-recorded.test.ts`. BOTH simulate two consecutive `logged_out_indicator` misses → assert `session_loss` envelope. The recorded variant pins zero-regression of v2.1d under the extended machinery." (c) Add Hard Criterion #15a.

### 5. `totp-secret-zeroing-perimeter` `[SOLO — byok-r3-NEW-1]`
- **Plan section:** Threat Model Steps 11-14 (lines ~355-364); Decision 18 (line ~642)
- **Claim:** Threat Model Step 13-14 says "Plaintext credential buffer zeroed via `Buffer.fill(0)` immediately after YAML write. Same pattern as v2.1d." The v2.1d pattern was designed when the only secret in the YAML was the decrypted JSON payload buffer. Patch A inlines `totp_secret` into the generated script body **string**, which gets interpolated into the YAML text by `buildAutomationYaml`. In-memory artifacts now include: (a) decrypted `ReplayCredentialPayload` JSON buffer — zeroed today, (b) generated script source as JS string — **NOT zeroable** (V8 strings are immutable), (c) assembled YAML string — same problem, (d) `Buffer.from(yamlString)` written by fs.writeFile — should be zeroed in finally but plan doesn't specify. Decision 18's rationale explicitly says "marginal privacy increment is bounded by the existing unlink-in-finally + `Buffer.fill(0)` zeroing pattern" — that bounding argument fails for the script-source and YAML-string surfaces.
- **Suggested patch:** Extend Threat Model Step 13-14 to enumerate the four in-memory artifacts: (i) decrypted payload buffer — zeroed; (ii) script source string + assembled YAML string — **NOT zeroable** (V8 immutable), bounded only by GC + process lifetime + Fly ephemerality; (iii) `Buffer.from(yamlString)` pre-`fs.writeFile` — zero in finally. Add explicit comment in `replay-zap-auth.ts` that script-source string holds `totp_secret` plaintext until GC. Add `dast-replay-yaml-cleanup.test.ts` sibling assertion: pre-write Buffer is zeroed in finally even when `spawnExternal` rejects.

### 6. `base32-validator-and-script-injection` `[SOLO — byok-r3-NEW-2]`
- **Plan section:** M1 step 8 (line ~475); `har_totp_secret_invalid` error code (line ~287); M3 step 3 (lines ~510-516)
- **Claim:** Patch A inlines `totp_secret` directly into the generated JS script body. **The plan never specifies the base32 validator regex** (only the error code `har_totp_secret_invalid` is declared) AND **never specifies the substitution discipline** (raw vs. JSON.stringify vs. validated-strict). Three threat models:
  - Raw substitution: a `totp_secret` containing `"; eval(maliciousJs()); var x ="` breaks out of the string literal. Anyone with `manage_integrations` could RCE the depscanner Fly machine — within-org credential escalation real.
  - `JSON.stringify`'d: safe against ASCII script-injection, NOT against U+2028 / U+2029 line-terminator injection (valid JSON, breaks JS string literals pre-ES2019; historical CVE source for templating systems).
  - Strict-validated to `/^[A-Z2-7]+={0,6}$/`: safe by construction. RFC 4648 base32 alphabet excludes all script-relevant characters.
- **Suggested patch:** Triple-defense:
  1. Add to `dast-har-constants.ts`: `export const TOTP_BASE32_RE = /^[A-Z2-7]+={0,6}$/;` + `TOTP_MAX_SECRET_LEN = 256`.
  2. M1 step 8: `validateReplayPayload` rejects with `har_totp_secret_invalid` if `!TOTP_BASE32_RE.test(secret)` or `secret.length > 256`. Reject U+2028 / U+2029 explicitly in ALL string fields (generic protection beyond TOTP).
  3. M3 step 3: script generator MUST use `JSON.stringify(payload.totp_secret)` even though the strict regex makes raw substitution safe — defense in depth.
  4. Tests in `dast-credential-validate.replay.test.ts`: hostile-secret cases (`";eval(1);"`, U+2028 inside, embedded null byte, >256 chars — all rejected). Test in `dast-replay-auth-config.test.ts`: emitted script parses via `new vm.Script(source)` (already in pragmatist's `script parseability` describe); ADD assertion that `SECRET` variable equals the literal input string after eval.

## P2 — Quality Gaps (12)

| ID | Finding | Source |
|---|---|---|
| skeptic-r3-f4 | `dast-replay-contracts.test.ts` grep walker regex misses switch/case + `.includes()` patterns | skeptic + test-strategy |
| skeptic-r3-f5 | UnsupportedAuthStrategyError silently rebrands v2.1a message at auth-config.ts:93 — grep-verified 0 consumers, but should be audited change not incidental drift | architect |
| skeptic-r3-f6 | Vendored RFC 6238 helper is a new first-party crypto surface — add Risks entry | skeptic + architect |
| prag-r3-1 | M0 step 6 full re-auth-cycle validation is heavy in 2-day M0 budget — bump to 2.5d or descope step 6 | pragmatist |
| prag-r3-3 | `dast-replay-contracts.test.ts` strategy-coverage describe is forward-compat insurance for hypothetical 6th strategy — trim to single describe | pragmatist + scope-cutter |
| prag-r3-4 | Patch D in-PR session-loss extension stacks recorded regression risk onto replay PR — pick Patch D(a) keep + force-include regression auditor, or D(b) descope to v1.1 | architect + scope-cutter |
| SC-13-R3 | `[dast-replay-crypto]` log line emits without v1 consumer (alert deferred to v1.1) — drop and re-add cross-strategy in v1.1 | scope-cutter (re-cut) |
| SC-14-R3 | Sanitization-summary fields (`dropped_header_count`, `dropped_bytes`, `kept_header_count`) ride on detail panel that's deferred to v1.1 — drop these 3 fields + sub-line | scope-cutter (re-cut) |
| SC-R3-1 | M3 estimate 3d undersized for Patch D scope — bump to 3.5d OR offer D(b) descope | scope-cutter |
| ARCH-R3-2 | Patch D step 7b(b) "recorded: re-invoke browser-auth flow" elides that recorded has NO in-scan re-invoke point — split into (b-replay) + (b-recorded) with explicit asymmetry | architect |
| ARCH-R3-4 | ARCH-NEW-6 engine-downgrade cited site (1756) doesn't grep-match — 4 candidate `engine === 'zap'` sites exist; pick the central resolver | architect |
| byok-r3-NEW-3 | TS-side `_helpers/totp-rfc6238.ts` debug-side-channel risk — explicitly note test-only at scan time + canary-suite coverage | byok-secrets |

## P3 — Nits & Opportunities (14)

- **skeptic-r3-f7** Base32 normalization (lowercase/padding/whitespace) not specified
- **skeptic-r3-f8** Hard criteria #15 #16 still tautological with CI green (carry from prag-r2-3)
- **SC-11-R3** Drop the forward-compat decrypt-switch describe entirely (now consolidated but still dead-weight insurance)
- **SC-15-R3** `flag_chips` union still has 5 variants when FE renders 3 — trim to match
- **SC-R3-2** M0 step 0 community-recipe check has no decision branch — either add one or drop
- **SC-R3-3** Roll #15 + #16 into the CI-tautology line for consistency
- **SC-R3-4** Add Decision 19 documenting v1-scope-intentionally-heavy on threat-model
- **ARCH-R3-5** `RECORDED_AUTH_BUDGET_MIN → AUTH_SETUP_BUDGET_MIN` rename surface crosses tests
- **TSA3-2** RFC 6238 cite `§5.1` should be `Appendix B` (4 sites)
- **TSA3-3** M0 step 6 cookie-kill mechanism unpinned (recommend `/JSON/httpSessions/action/removeSession/`)
- **TSA3-4** M5 optional real-ZAP scenario enumeration missing
- **OS-NEW-2-r3** Canary-leak-suite helper extraction (defensible given v1.1 Postman support)
- **byok-r3-NEW-4** RFC 6238 secret identifier collision risk — recommend `__DEPTEX_TOTP_SECRET` prefix

## Suggested Plan Amendments — Patch I (single consolidated patch, ~30 minutes)

The 6 P1 findings consolidate into **one focused patch** since they're all narrow plan-text edits:

```
Patch I — Round 3 P1 cleanup (~30 min plan editing)

I1. M2 step 1: replace Patch B's recommendation with concrete path-gated diff against backend/src/index.ts (P1 #1)
I2. M3 step 7b: rewrite (a) to cite control-plane.ts:276 not pipeline.ts; (d) test threshold = actual >=4 not 2 (P1 #2)
I3. Patch G cron: commit to creating scan_jobs_retention cron in M5 (or descope to worker-side delayed-null pattern) (P1 #3)
I4. M3 step 7b: add dast-pipeline-session-loss-recorded.test.ts to file inventory + step 7b(d) + criterion #15a (P1 #4)
I5. Threat Model Step 13-14: enumerate 4 in-memory artifacts; clarify script-source + YAML strings are GC-bounded not zeroed (P1 #5)
I6. Add TOTP_BASE32_RE + TOTP_MAX_SECRET_LEN to dast-har-constants.ts; M1 step 8 spec; M3 step 3 JSON.stringify discipline; U+2028/U+2029 generic rejection; hostile-secret tests in M1 step 9 + M3 step 11 (P1 #6)
```

P2 patches optional bundle (~20 min):
- SC-13-R3 + SC-14-R3 (drop crypto log + sanitization sub-line fields)
- prag-r3-1 + SC-R3-1 (bump M0 to 2.5d + M3 to 3.5d → total 12 days)
- ARCH-R3-2 (split Patch D step 7b(b) into recorded/replay asymmetric)
- ARCH-R3-4 (grep for engine-selection resolver site; cite real file:line)

P3 patches deferrable to /implement-time inline edits.

## Findings by Axis

| Axis | Count | Highest severity |
|---|---|---|
| Plan-citation accuracy | 4 | P1 (×3) |
| Missing regression test | 1 | P1 |
| Patch A privacy tightening | 3 | P1 (×2) |
| Test-suite consolidation | 3 | P2 |
| Scope cuts (re-cut from Round 2) | 5 | P2 (×2) |
| M0/M3 budget realism | 2 | P2 |
| Test-vector cite nits | 2 | P3 |
| Observability/UX trim | 3 | P2/P3 |
| Identifier/naming hygiene | 4 | P3 |

## Persona Coverage Map

| Persona | R3 findings (P0/P1/P2/P3) | Vote |
|---|---|---|
| skeptic | 0 / 3 / 3 / 2 | REVISE (implied) |
| pragmatist | 0 / 0 / 4 / 0 | **READY** |
| scope-cutter | 0 / 0 / 5 / 4 | REVISE-with-minor-cuts |
| architect | 0 / 1 / 3 / 1 | REVISE |
| test-strategy-auditor | 0 / 1 / 0 / 3 | **READY-with-1-P2** |
| opportunity-scout | 0 / 0 / 0 / 1 | **READY** |
| byok-secrets-auditor | 0 / 2 / 1 / 2 | REVISE |

## Trajectory

```
Round 1:  7 P0  / 19 P1  / 22 P2 / 24 P3   → REWORK
Round 2:  1 P0  /  8 P1  / 14 P2 / 10 P3   → REWORK
Round 3:  0 P0  /  6 P1  / 12 P2 / 14 P3   → REVISE (substantially READY)
```

## Recommended Next Step

**Apply Patch I (single ~30-min plan edit, addresses all 6 P1s)** and proceed to `/implement`. The P1s are concrete plan-text accuracy fixes + 1 missing test entry + 2 Patch A tightenings — none require additional research or interview rounds.

**Alternative:** accept REVISE-with-known-residuals and address during `/implement`. Risk: skeptic-r3-f1 (broken Patch B diff) and skeptic-r3-f2 (Patch D wrong file:line) would each cost 0.5-1 day of /implement time to discover empirically vs. 5 minutes to fix in the plan now. Strong recommendation: take Patch I before /implement.

After Patch I: optionally re-run `/review-plan` once more (expected verdict: READY). Then `/create-worktree dast-har-import` → `/implement`.
