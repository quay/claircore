SELECT DISTINCT ON (updater)
	id
FROM
	update_operation
WHERE
	kind = 'vulnerability'
ORDER BY
	updater,
	id DESC;
