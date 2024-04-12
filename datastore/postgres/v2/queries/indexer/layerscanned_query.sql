SELECT
	EXISTS (
		SELECT
			1
		FROM
			scanned_layer
			JOIN scanner ON scanner.id = scanned_layer.scanner_id
			JOIN layer ON layer.id = scanned_layer.layer_id
		WHERE
			scanner.name = $1
			AND scanner.version = $2
			AND scanner.kind = $3
			AND layer.hash = $4);
