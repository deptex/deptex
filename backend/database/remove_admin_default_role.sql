-- Migration: Remove admin as a default role
-- This removes admin roles that were created as default roles
-- Only owner and member should be default roles

-- Delete admin roles that are marked as default
DELETE FROM organization_roles
WHERE name = 'admin' AND is_default = true;

