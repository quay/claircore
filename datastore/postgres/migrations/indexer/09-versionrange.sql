DO $$ 
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_type WHERE typname = 'versionrange') THEN
        CREATE TYPE VersionRange AS RANGE ( SUBTYPE = integer[10]);
    END IF;
END $$;
