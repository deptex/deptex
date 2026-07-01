-- phase70: capture WHY an Aegis fix failed, so the task chat can show its work
-- instead of a generic "I couldn't finish this safely".
--
-- When a fix fails, the worker records what it actually TRIED (the diff the model
-- produced, even if it didn't apply) and the real blocker (test/apply error tail,
-- repair count) into failure_details, plus the human-facing headline / explanation
-- / next-step copy it derived from the failure category. The FixFailureCard reads
-- this to render a transparent "here's where I got stuck" card.
--
-- Shape (all optional):
--   {
--     "category":     "tests_failed" | "diff_too_large" | "budget_wall_clock" |
--                     "not_fixable" | "unsupported_language" | ...,
--     "headline":     "The change didn't pass the checks",
--     "explanation":  "I applied a fix to src/x.ts but the typecheck still failed…",
--     "nextStep":     "The diff I tried and the error are below — it likely needs…",
--     "attemptedDiff":"--- a/… +++ b/… …",
--     "errorOutput":  "<test stderr/stdout tail>",
--     "repairAttempts": 2,
--     "stepsCompleted": ["cloned", "edited"]
--   }

ALTER TABLE public.project_security_fixes
  ADD COLUMN IF NOT EXISTS failure_details jsonb;
