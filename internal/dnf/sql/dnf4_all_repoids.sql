SELECT DISTINCT
  repoid
FROM
  trans_item
  JOIN (
    SELECT
      max(id) AS uniq
    FROM
      trans_item
    WHERE
      action <> 8
    GROUP BY
      item_id
  ) ON (uniq = trans_item.id)
  JOIN repo ON (repo.id = repo_id);
