INSERT INTO package (name, kind, version, norm_kind, norm_version, module, arch, id)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
ON CONFLICT
    DO NOTHING;

