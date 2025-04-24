CREATE INDEX IF NOT EXISTS uo_enrich_enrich_idx ON uo_enrich (enrich);
CREATE INDEX IF NOT EXISTS uo_enrich_uo_idx ON uo_enrich (uo);
CREATE INDEX IF NOT EXISTS enrichment_updater_idx ON enrichment (updater);
