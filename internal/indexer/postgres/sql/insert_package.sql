INSERT INTO package (name, kind, version, norm_kind, norm_version, module, arch)
    VALUES ($1, $2, $3, $4, $5::int[], $6, $7)
ON CONFLICT (name, kind, version, module, arch)
    DO NOTHING;

