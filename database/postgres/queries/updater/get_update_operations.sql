SELECT DISTINCT ON (updater)
    ref,
    updater,
    fingerprint,
    date,
    kind
FROM
    update_operation
ORDER BY
    id DESC;

