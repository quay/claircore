INSERT INTO
    dist (
        name,
        did,
        version,
        version_code_name,
        version_id,
        arch,
        cpe,
        pretty_name
    )
VALUES
    ($1, $2, $3, $4, $5, $6, $7, $8) ON CONFLICT (
        name,
        did,
        version,
        version_code_name,
        version_id,
        arch,
        cpe,
        pretty_name
    ) DO NOTHING;
