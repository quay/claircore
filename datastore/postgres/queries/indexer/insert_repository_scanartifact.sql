WITH repositories AS (
    SELECT
        id AS repo_id
    FROM
        repo
    WHERE
        name = $1
        AND key = $2
        AND uri = $3
),
scanner AS (
    SELECT
        id AS scanner_id
    FROM
        scanner
    WHERE
        name = $4
        AND version = $5
        AND kind = $6
),
layer AS (
    SELECT
        id AS layer_id
    FROM
        layer
    WHERE
        layer.hash = $7
)
INSERT INTO
    repo_scanartifact (layer_id, repo_id, scanner_id)
VALUES
    (
        (
            SELECT
                layer_id
            FROM
                layer
        ),
        (
            SELECT
                repo_id
            FROM
                repositories
        ),
        (
            SELECT
                scanner_id
            FROM
                scanner
        )
    ) ON CONFLICT DO NOTHING;
