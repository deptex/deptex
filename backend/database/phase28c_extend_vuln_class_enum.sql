-- Phase 28c — extend taint_engine_settings.vuln_classes_enabled DEFAULT to
-- include `weak_crypto` and `auth_bypass`.
--
-- Why: Phase 6.5's marathon-wave 88-CVE iterate baseline showed two CVEs
-- whose natural vuln_class falls outside the existing closed enum and got
-- silently dropped under `invalid_schema` at Gate 1:
--
--   * CVE-2022-23541 (jsonwebtoken `kid` claim with weak / attacker-
--     resolvable key) — natural class is `weak_crypto`: tainted data
--     influences a cryptographic primitive in a way that breaks its
--     security guarantees.
--   * CVE-2022-22978 (Spring Security RegexRequestMatcher newline auth
--     bypass) — natural class is `auth_bypass`: tainted data routes
--     around an authentication / authorization decision.
--
-- Both are real taint-flow classes (source → sink with a clear gate at the
-- sink) and belong in the engine taxonomy. Same shape as phase28b: this is
-- a plain text[] column DEFAULT change — `vuln_classes_enabled` is a
-- TEXT[] (NOT a Postgres ENUM type), so no `ALTER TYPE … ADD VALUE` is
-- required. Existing rows keep their stored `vuln_classes_enabled` value;
-- orgs that hadn't yet inserted a settings row pick up the new defaults
-- the next time they touch the panel.

ALTER TABLE taint_engine_settings
  ALTER COLUMN vuln_classes_enabled SET DEFAULT ARRAY[
    'sql_injection', 'ssrf', 'xss', 'path_traversal', 'command_injection',
    'prototype_pollution', 'deserialization', 'redos', 'file_upload',
    'open_redirect', 'log_injection', 'code_injection',
    'weak_crypto', 'auth_bypass'
  ];
