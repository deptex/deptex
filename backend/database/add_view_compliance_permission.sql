-- Migration to add view_compliance permission to all existing roles
-- This assumes permissions are stored as a JSONB object in the 'permissions' column of 'organization_roles'

-- Update all roles to have view_compliance = true if it doesn't exist?
-- Or should it only be for roles that are likely owners?
-- The user said "give me whatever sequel query". I'll default to adding it to Owners and Admins, or maybe everyone since it was added to default member role too.
-- Let's add it to everyone for simplicity, or maybe just owners?
-- "edit the add rule and the settings ... I also want View compliants add that permission"
-- I will add it to all roles for now as false, but true for owners.

-- Set view_compliance to true for 'owner' roles
UPDATE organization_roles
SET permissions = jsonb_set(permissions, '{view_compliance}', 'true'::jsonb)
WHERE name = 'owner';

-- Set view_compliance to false for other roles (unless we want them to have it by default?)
-- The code change I made to backend adds it as 'true' for 'member'.
-- So I should probably add it as 'true' for 'member' as well?
-- User didn't specify, but often new permissions are restricted. However, compliance seems like read-only.
-- I'll follow my backend change which set it to true for members.

UPDATE organization_roles
SET permissions = jsonb_set(permissions, '{view_compliance}', 'true'::jsonb)
WHERE name != 'owner';
