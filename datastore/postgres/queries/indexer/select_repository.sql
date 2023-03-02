SELECT
    id
FROM
    repo
WHERE
    name = $1
    AND key = $2
    AND uri = $3;
