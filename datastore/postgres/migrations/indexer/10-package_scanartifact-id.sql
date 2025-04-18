-- The package table only save one copy for each unique name+version of a package (and a few more fields).
-- It is possible an image has several packages with the same name+version (and the other fields)
-- in different locations. Without this migration, the IndexReport only tracks one of those packages
-- instead of a package for each unique location.
ALTER TABLE IF EXISTS package_scanartifact ADD COLUMN id BIGSERIAL;
