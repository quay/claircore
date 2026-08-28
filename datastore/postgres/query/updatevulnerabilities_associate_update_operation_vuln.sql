INSERT INTO
  uo_vuln (uo, vuln)
VALUES
  ($1, $2)
ON CONFLICT DO NOTHING;
