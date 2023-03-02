SELECT
    id
FROM
    dist
WHERE
    arch = $1
    AND cpe = $2
    AND did = $3
    AND name = $4
    AND pretty_name = $5
    AND version = $6
    AND version_code_name = $7
    AND version_id = $8;
