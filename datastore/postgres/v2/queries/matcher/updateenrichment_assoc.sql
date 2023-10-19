INSERT
INTO
	uo_enrich (enrich, updater, uo, date)
VALUES
	(
		(
			SELECT
				id
			FROM
				enrichment
			WHERE
				hash_kind = $1
				AND hash = $2
				AND updater = $3
		),
		$3,
		$4,
		transaction_timestamp()
	)
ON CONFLICT
DO
	NOTHING;
