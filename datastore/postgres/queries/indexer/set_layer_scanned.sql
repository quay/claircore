WITH scanner AS (
    SELECT
        id
    FROM
        scanner
    WHERE
        name = $2
        AND version = $3
        AND kind = $4
),
layer AS (
    SELECT
        id
    FROM
        layer
    WHERE
        hash = $1
)
INSERT INTO
    scanned_layer (layer_id, scanner_id)
VALUES
    (
        (
            SELECT
                id AS layer_id
            FROM
                layer
        ),
        (
            SELECT
                id AS scanner_id
            FROM
                scanner
        )
    ) ON CONFLICT (layer_id, scanner_id) DO NOTHING;
