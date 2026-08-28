SELECT
  id
FROM
  vuln
WHERE
  hash_kind = $1
  AND hash = $2;
