SELECT
    EXISTS(
        SELECT
            1
        FROM
            scanner
        WHERE
            name = $1
            AND version = $2
            AND kind = $3
    );
