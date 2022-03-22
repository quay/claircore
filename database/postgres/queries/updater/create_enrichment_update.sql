INSERT INTO update_operation (ref, updater, fingerprint, kind)
    VALUES ($1, $2, $3, 'enrichment')
RETURNING
    id;

