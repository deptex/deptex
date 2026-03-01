-- Phase 3A.1: Add GHSA advisory classification (GENERAL or MALWARE)
ALTER TABLE dependency_vulnerabilities
  ADD COLUMN IF NOT EXISTS classification TEXT DEFAULT 'GENERAL';
