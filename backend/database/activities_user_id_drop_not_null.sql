-- activities.user_id is NOT NULL but its FK is ON DELETE SET NULL.
-- When auth.admin.deleteUser fires, Postgres tries to null it and hits the NOT NULL constraint.
-- The null-attribution semantic (deleted user = unknown actor) is correct here.
ALTER TABLE public.activities ALTER COLUMN user_id DROP NOT NULL;
