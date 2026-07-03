-- Permit the autonomous-agent strategy on the fix-row claim queue.
--
-- The Aegis task path (acceptTask -> one project_security_fixes row per target
-- with strategy='agent') reuses project_security_fixes as its claimable unit on
-- the existing Fly claim pool. Without widening this CHECK the accept insert
-- fails on the very first agentic row. Purely additive — no data change.

ALTER TABLE public.project_security_fixes
  DROP CONSTRAINT IF EXISTS project_security_fixes_strategy_check;

ALTER TABLE public.project_security_fixes
  ADD CONSTRAINT project_security_fixes_strategy_check CHECK (
    strategy = ANY (ARRAY[
      'bump_version'::text,
      'code_patch'::text,
      'add_wrapper'::text,
      'pin_transitive'::text,
      'remove_unused'::text,
      'fix_semgrep'::text,
      'remediate_secret'::text,
      'fix_iac'::text,
      'bump_base_image'::text,
      'sanitize_dataflow'::text,
      'patch_handler'::text,
      'agent'::text
    ])
  );
