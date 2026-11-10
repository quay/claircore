-- Widen the alias table's id column and the columns referencing it from
-- INTEGER to BIGINT, to match the vuln table's id column.
--
-- The alias_id_seq sequence backing alias.id is defined as INTEGER and
-- can be exhausted, at which point no new aliases can be inserted and
-- vulnerability updates fail.
--
-- Altering an identity column's type also alters the backing sequence,
-- so no separate ALTER SEQUENCE is needed.
ALTER TABLE alias
ALTER COLUMN id TYPE BIGINT;

ALTER TABLE vulnerability_alias
ALTER COLUMN alias TYPE BIGINT;

ALTER TABLE vulnerability_self
ALTER COLUMN self TYPE BIGINT;
