WITH manifests AS (
    SELECT
        id AS manifest_id
    FROM
        manifest
    WHERE
        hash = $1
),
layers AS (
    SELECT
        id AS layer_id
    FROM
        layer
    WHERE
        hash = $2
)
INSERT INTO
    manifest_layer (manifest_id, layer_id, i)
VALUES
    (
        (
            SELECT
                manifest_id
            FROM
                manifests
        ),
        (
            SELECT
                layer_id
            FROM
                layers
        ),
        $3
    ) ON CONFLICT DO NOTHING;
