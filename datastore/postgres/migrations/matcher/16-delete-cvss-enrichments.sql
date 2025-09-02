-- Delete all update_operations for cvss enrichments to trigger cvss enrichment deletion
DELETE FROM update_operation WHERE updater = 'clair.cvss' AND kind = 'enrichment';

-- Clean up any orphaned enrichment records
DELETE FROM enrichment e1 USING
    enrichment e2
    LEFT JOIN uo_enrich ue
        ON e2.id = ue.enrich
    WHERE ue.enrich IS NULL
    AND e2.updater = 'clair.cvss'
    AND e1.id = e2.id;
