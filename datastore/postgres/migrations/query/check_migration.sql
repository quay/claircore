SELECT
  EXISTS (
    SELECT
      1
    FROM
      "@table"
    WHERE
      version = $1
  );
