ALTER TABLE indexreport
ADD COLUMN IF NOT EXISTS updated_at timestamptz NOT NULL DEFAULT now();

UPDATE indexreport
SET
  state = COALESCE(NULLIF(state, ''), scan_result ->> 'state')
WHERE
  state IS NULL
  OR state = '';

CREATE INDEX IF NOT EXISTS indexreport_partial_retry_idx ON indexreport (updated_at)
WHERE
  state = 'IndexPartial';
