WITH source_package AS (
    SELECT
        id AS source_id
    FROM
        package
    WHERE
        name = $1
        AND kind = $2
        AND version = $3
        AND module = $4
        AND arch = $5
),
binary_package AS (
    SELECT
        id AS package_id
    FROM
        package
    WHERE
        name = $6
        AND kind = $7
        AND version = $8
        AND module = $9
        AND arch = $10
),
scanner AS (
    SELECT
        id AS scanner_id
    FROM
        scanner
    WHERE
        name = $11
        AND version = $12
        AND kind = $13
),
layer AS (
    SELECT
        id AS layer_id
    FROM
        layer
    WHERE
        layer.hash = $14)
INSERT INTO package_scanartifact (layer_id, package_db, repository_hint, package_id, source_id, scanner_id)
    VALUES ((
            SELECT
                layer_id
            FROM
                layer),
            $15,
            $16,
            (
                SELECT
                    package_id
                FROM
                    binary_package),
                (
                    SELECT
                        source_id
                    FROM
                        source_package),
                    (
                        SELECT
                            scanner_id
                        FROM
                            scanner))
            ON CONFLICT
                DO NOTHING;

