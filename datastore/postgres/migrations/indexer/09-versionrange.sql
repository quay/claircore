-- The indexer DB needs a VersionRange function for the affectedManifest
-- method, it already exists in the matcher DB so the existence check is
-- imperative.
DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'versionrange') THEN
        CREATE TYPE VersionRange AS RANGE ( SUBTYPE = integer[10]);
    END IF;
END $$;
