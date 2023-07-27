-- A unique index is needed on the materialized view to facilitate CONCURRENT refreshing.
CREATE UNIQUE INDEX idx_updater_uniq ON latest_update_operations(updater);
