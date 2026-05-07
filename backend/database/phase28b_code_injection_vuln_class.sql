-- Phase 28b — extend taint_engine_settings.vuln_classes_enabled DEFAULT to
-- include `code_injection`.
--
-- Why: Phase 6.5's 88-CVE iterate baseline observed Qwen emitting
-- `vuln_class: code_injection` for SpEL-style CVEs (e.g. CVE-2023-34053
-- Spring SpEL eval). The closed enum in `taint-engine/spec.ts` and the
-- generator's zod schema both rejected the spec under `invalid_schema`,
-- which silently dropped 1 of 88 corpus CVEs (3.4% with the two adjacent
-- DoS-class CVEs that are correctly out of taint scope). `code_injection`
-- is a real taint-flow class — tainted data interpreted as code by the
-- runtime — so it belongs in the engine taxonomy. Vuln classes that are
-- genuinely not taint-modelable (DoS, XML expansion, HTTP/2 reset) now
-- surface via the generator's `vuln_class_out_of_scope` failure code
-- instead of being silently bucketed as schema noise.
--
-- This migration only changes the column DEFAULT (applies to new orgs
-- that haven't yet inserted a settings row). Existing rows keep their
-- current `vuln_classes_enabled` value — orgs that previously customized
-- the enabled set keep their explicit choice; orgs that opted into the
-- old default get code_injection enabled the next time they touch the
-- settings row through the UI (the GET-synthesizer fallback uses the new
-- value).

ALTER TABLE taint_engine_settings
  ALTER COLUMN vuln_classes_enabled SET DEFAULT ARRAY[
    'sql_injection', 'ssrf', 'xss', 'path_traversal', 'command_injection',
    'prototype_pollution', 'deserialization', 'redos', 'file_upload',
    'open_redirect', 'log_injection', 'code_injection'
  ];
