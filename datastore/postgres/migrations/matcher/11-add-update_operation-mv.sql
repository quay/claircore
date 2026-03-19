-- Create materialized view that maintains the lastest update_operation id per updater.
CREATE MATERIALIZED VIEW IF NOT exists latest_update_operations AS
SELECT DISTINCT
  ON (updater) id,
  kind,
  updater
FROM
  update_operation
ORDER BY
  updater,
  id DESC;
