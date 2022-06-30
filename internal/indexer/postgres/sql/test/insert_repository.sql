INSERT INTO repo (name, key, uri, id)
    VALUES ($1, $2, $3, $4)
ON CONFLICT
    DO NOTHING;

