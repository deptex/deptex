-- phase43: replace single billing_email_override with a TEXT[] array of recipients.
--
-- Empty array falls back to "send to everyone with manage_billing perm". The UI in
-- Settings → Billing exposes this as a chip-list so orgs can route alerts to
-- finance@yourco.com or any specific subset of teammates.

ALTER TABLE organization_billing
  ADD COLUMN billing_email_recipients TEXT[] NOT NULL DEFAULT '{}';

UPDATE organization_billing
SET billing_email_recipients = ARRAY[billing_email_override]
WHERE billing_email_override IS NOT NULL AND billing_email_override <> '';

ALTER TABLE organization_billing
  DROP COLUMN billing_email_override;
