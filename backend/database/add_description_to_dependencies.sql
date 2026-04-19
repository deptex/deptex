-- Migration: Add description column to dependencies table
-- Stores the npm package description (e.g. "React is a JavaScript library for building user interfaces.")

ALTER TABLE dependencies
ADD COLUMN IF NOT EXISTS description TEXT;

COMMENT ON COLUMN dependencies.description IS 'Package description from npm registry';
