INSERT INTO scanned_layer (layer_id, scanner_id)
	VALUES ((
			SELECT
				id
			FROM
				layer
			WHERE
				hash = $1), (
				SELECT
					id
				FROM
					scanner
				WHERE
					name = $2
					AND version = $3
					AND kind = $4))
	ON CONFLICT (layer_id,
		scanner_id)
	DO NOTHING;
