DELETE FROM manifest
WHERE hash = ANY ($1::text[])
RETURNING
	manifest.hash;
