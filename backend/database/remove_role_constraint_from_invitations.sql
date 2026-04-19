-- Migration: Remove role constraint from organization_invitations to support custom roles
-- Run this in your Supabase SQL Editor

-- Drop the existing CHECK constraint on role
ALTER TABLE organization_invitations 
DROP CONSTRAINT IF EXISTS organization_invitations_role_check;

-- The role column will now accept any text value, allowing custom roles
-- Validation will be handled at the application level

