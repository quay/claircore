DELETE FROM update_operation
WHERE ref = ANY ($1::uuid[]);
