-- Widen the vulnerability FK columns in the alias tables from INTEGER to BIGINT
-- to match the vuln.id column.
ALTER TABLE vulnerability_alias
ALTER COLUMN vulnerability TYPE BIGINT;

ALTER TABLE vulnerability_self
ALTER COLUMN vulnerability TYPE BIGINT;
