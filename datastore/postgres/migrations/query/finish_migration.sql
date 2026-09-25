UPDATE "@table"
SET
  finished_at = statement_timestamp()
WHERE
  version = $1;
