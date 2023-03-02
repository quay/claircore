DELETE FROM
    manifest
WHERE
    hash = ANY($1::TEXT[]) RETURNING manifest.hash;
