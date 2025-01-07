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
			name = ? AND
			epoch = ? AND
			version = ? AND
			release = ? AND
			arch = ?
		) USING (item_id);
