INSERT INTO manifest (hash)
    VALUES ($1)
ON CONFLICT
    DO NOTHING;
