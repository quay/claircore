WITH ins AS (
INSERT INTO enrichment (hash_kind, hash, updater, tags, data)
        VALUES ($1, $2, $3, $4, $5)
    ON CONFLICT (hash_kind, hash)
        DO NOTHING)
    INSERT INTO uo_enrich (enrich, updater, uo, date)
        VALUES ((
                SELECT
                    id
                FROM
                    enrichment
                WHERE
                    hash_kind = $1
                    AND hash = $2
                    AND updater = $3),
                $3,
                $6,
                transaction_timestamp())
    ON CONFLICT
        DO NOTHING;

