INSERT INTO
  alias (namespace, name)
SELECT
  ns.id,
  $2
FROM
  alias_namespace AS ns
WHERE
  ns.namespace = $1
ON CONFLICT DO NOTHING;
