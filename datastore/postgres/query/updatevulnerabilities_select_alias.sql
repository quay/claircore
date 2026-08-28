SELECT
  a.id
FROM
  alias AS a
  JOIN alias_namespace AS ns ON a.namespace = ns.id
WHERE
  ns.namespace = $1
  AND a.name = $2;
