SELECT 1 WHERE ROW ('vulnerability') = ALL (SELECT kind FROM update_operation
	WHERE ref = $1 OR ref = $2);
