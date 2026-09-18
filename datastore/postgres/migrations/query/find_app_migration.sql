SELECT
  id
FROM
  "@table"
WHERE
  application_work_required = TRUE
  AND finished_at IS NULL;
