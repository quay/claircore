INSERT INTO dist (name, did, version, version_code_name, version_id, arch, cpe, pretty_name, id)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
ON CONFLICT
    DO NOTHING;

