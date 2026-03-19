-- file
CREATE TABLE IF NOT EXISTS file (
  id BIGSERIAL PRIMARY KEY,
  path text NOT NULL,
  kind text NOT NULL
);

CREATE UNIQUE INDEX IF NOT EXISTS file_unique_idx ON file (path, kind);

-- FileScanArtifact
-- A relation linking discovered file to a layer
CREATE TABLE IF NOT EXISTS file_scanartifact (
  file_id bigint REFERENCES file (id) ON DELETE CASCADE,
  scanner_id bigint REFERENCES scanner (id) ON DELETE CASCADE,
  layer_id bigint REFERENCES layer (id) ON DELETE CASCADE,
  PRIMARY KEY (layer_id, scanner_id, file_id)
);

ALTER TABLE package_scanartifact
ADD COLUMN filepath text;
