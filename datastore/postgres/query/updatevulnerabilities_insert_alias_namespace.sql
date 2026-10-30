INSERT INTO
  alias_namespace (namespace)
VALUES
  ($1)
ON CONFLICT DO NOTHING;
