INSERT INTO repo (name, key, uri, cpe)
    VALUES ($1, $2, $3, $4)
ON CONFLICT (name, key, uri)
    DO NOTHING;

