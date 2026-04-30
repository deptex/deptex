-- Drop the unused framework_models_used JSONB column from taint_engine_runs.
--
-- Added in phase26_taint_engine.sql with the intent of recording which
-- framework specs each run used, but the worker's writeRun() never writes
-- to it and no read site references it. Dead schema; remove cleanly.

ALTER TABLE public.taint_engine_runs
  DROP COLUMN IF EXISTS framework_models_used;
