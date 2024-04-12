WITH ordered_ops AS (
	SELECT
		array_agg(ref ORDER BY date DESC) AS refs
	FROM
		update_operation
	GROUP BY
		updater
)
SELECT
	ordered_ops.refs[$1:]
FROM
	ordered_ops
WHERE
	array_length(ordered_ops.refs, 1) > $2;
