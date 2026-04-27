-- When a user leaves an org, transfer creator-ownership of any Aegis threads
-- they own in that org to the oldest remaining participant. Orphaned threads
-- (no remaining participants) are deleted.

CREATE OR REPLACE FUNCTION handle_aegis_creator_leaves_org()
RETURNS TRIGGER
LANGUAGE plpgsql
SECURITY DEFINER
SET search_path = public
AS $$
DECLARE
  t RECORD;
  new_owner UUID;
BEGIN
  FOR t IN
    SELECT id FROM aegis_chat_threads
    WHERE organization_id = OLD.organization_id
      AND user_id = OLD.user_id
  LOOP
    DELETE FROM aegis_chat_participants
    WHERE thread_id = t.id AND user_id = OLD.user_id;

    SELECT user_id INTO new_owner
    FROM aegis_chat_participants
    WHERE thread_id = t.id
    ORDER BY joined_at ASC
    LIMIT 1;

    IF new_owner IS NULL THEN
      DELETE FROM aegis_chat_threads WHERE id = t.id;
    ELSE
      UPDATE aegis_chat_threads SET user_id = new_owner WHERE id = t.id;
    END IF;
  END LOOP;
  RETURN OLD;
END;
$$;

DROP TRIGGER IF EXISTS aegis_creator_leaves_org ON organization_members;
CREATE TRIGGER aegis_creator_leaves_org
  AFTER DELETE ON organization_members
  FOR EACH ROW
  EXECUTE FUNCTION handle_aegis_creator_leaves_org();
