INSERT INTO
    scanner (name, version, kind)
VALUES
    ($1, $2, $3) ON CONFLICT (name, version, kind) DO NOTHING;
