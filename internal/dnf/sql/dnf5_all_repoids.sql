SELECT DISTINCT
  repoid
FROM
  trans_item
  JOIN (
    SELECT
      max(i.id) AS uniq
    FROM
      trans_item AS i
      JOIN trans_item_action AS a ON (i.action_id = a.id)
    WHERE
      a.Name <> 'Remove'
    GROUP BY
      i.item_id
  ) ON (uniq = trans_item.id)
  JOIN repo ON (repo.id = repo_id);
