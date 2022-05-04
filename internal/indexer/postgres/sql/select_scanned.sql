SELECT
    EXISTS (
        SELECT
            1
        FROM
            layer
            JOIN scanned_layer ON scanned_layer.layer_id = layer.id
        WHERE
            layer.hash = $1
            AND scanned_layer.scanner_id = $2);

