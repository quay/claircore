SELECT
	repoid
FROM
	trans_item
	JOIN (
		SELECT
			max(id) AS uniq
		FROM
			trans_item
		WHERE
			action <> ?
		GROUP BY
			item_id
		) ON (uniq = trans_item.id)
	JOIN
		repo ON (repo.id = repo_id)
	JOIN (
		SELECT
			item_id
		FROM 
			rpm
		WHERE
			? = name ||'-'||
				CASE
					WHEN epoch = 0 THEN ''
					ELSE epoch || ':'
				END ||
				version ||'-'||
				release ||'.'||
				arch
		) USING (item_id);
