SELECT
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
  JOIN repo ON (repo.id = repo_id)
  JOIN (
    SELECT
      item_id
    FROM
      rpm AS r
      JOIN pkg_name AS n ON (r.name_id = n.id)
      JOIN arch AS a ON (r.arch_id = a.id)
    WHERE
      n.name = ?
      AND r.epoch = ?
      AND r.version = ?
      AND r.release = ?
      AND a.name = ?
  ) USING (item_id);
