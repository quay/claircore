package migrations

const (
	// this migration modifies the database to add a
	// delete cascade constraint to the enrichments FKs
	migration5 = `
ALTER TABLE uo_enrich
DROP CONSTRAINT uo_enrich_uo_fkey,
DROP CONSTRAINT uo_enrich_enrich_fkey,
ADD CONSTRAINT uo_enrich_uo_fkey FOREIGN KEY (uo) REFERENCES update_operation (id) ON DELETE CASCADE,
ADD CONSTRAINT uo_enrich_enrich_fkey FOREIGN KEY (enrich) REFERENCES enrichment (id) ON DELETE CASCADE;
`
)
