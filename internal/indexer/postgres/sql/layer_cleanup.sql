DELETE FROM layer
WHERE NOT EXISTS (
        SELECT
        FROM
            manifest_layer
        WHERE
            manifest_layer.layer_id = layer.id);

