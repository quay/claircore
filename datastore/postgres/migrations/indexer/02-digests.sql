/* First lets drop all the foreign key constraints so we can
   work with the manifest and layer tables without dependencies */
ALTER TABLE dist_scanartifact DROP CONSTRAINT dist_scanartifact_layer_hash_fkey;
ALTER TABLE indexreport DROP CONSTRAINT indexreport_manifest_hash_fkey;
ALTER TABLE manifest_index DROP CONSTRAINT manifest_index_manifest_hash_fkey;
ALTER TABLE manifest_layer DROP CONSTRAINT manifest_layer_layer_hash_fkey;
ALTER TABLE manifest_layer DROP CONSTRAINT manifest_layer_manifest_hash_fkey;
ALTER TABLE package_scanartifact DROP CONSTRAINT package_scanartifact_layer_hash_fkey;
ALTER TABLE repo_scanartifact DROP CONSTRAINT repo_scanartifact_layer_hash_fkey;
ALTER TABLE scanned_layer DROP CONSTRAINT scanned_layer_layer_hash_fkey;
ALTER TABLE scanned_manifest DROP CONSTRAINT scanned_manifest_manifest_hash_fkey;


/* next lets alter the manifest and layer tables
   - add bigserial id columns to layer and manifest tables
   - drop existing primary key and add the id as primary key for both tables
   - add unique constraints on hash so duplicate layers and manifest hashes are not allowed
 */
ALTER TABLE manifest ADD COLUMN id bigserial;
ALTER TABLE layer ADD COLUMN id bigserial;

ALTER TABLE manifest DROP CONSTRAINT manifest_pkey;
ALTER TABLE manifest ADD PRIMARY KEY (id);
CREATE INDEX ON manifest(hash);
ALTER TABLE layer DROP CONSTRAINT layer_pkey;
ALTER TABLE layer ADD PRIMARY KEY (id);
CREATE INDEX ON layer(hash);

ALTER TABLE manifest ADD CONSTRAINT manifest_hash_unique UNIQUE (hash);
ALTER TABLE layer ADD CONSTRAINT layer_hash_unique UNIQUE (hash);

/* next for each table with a foreign key to layer or manifest table:
   - create the layer or manifest id column
   - create new foreign key relationships that replace the hash strings
   - insert layer and manifest ids into new columns*/
ALTER TABLE dist_scanartifact ADD COLUMN layer_id bigint;
ALTER TABLE dist_scanartifact ADD FOREIGN KEY (layer_id) REFERENCES layer(id);
UPDATE dist_scanartifact AS ds SET layer_id = (SELECT id FROM layer WHERE hash = ds.layer_hash);

ALTER TABLE indexreport ADD COLUMN manifest_id bigint;
ALTER TABLE indexreport ADD FOREIGN KEY (manifest_id) REFERENCES manifest(id);
UPDATE indexreport AS ir SET manifest_id = (SELECT id FROM manifest WHERE hash = ir.manifest_hash);

ALTER TABLE manifest_index ADD COLUMN manifest_id bigint;
ALTER TABLE manifest_index ADD FOREIGN KEY (manifest_id) REFERENCES manifest(id);
UPDATE manifest_index AS r SET manifest_id = (SELECT id FROM manifest WHERE hash = r.manifest_hash);

ALTER TABLE manifest_layer ADD COLUMN manifest_id bigint;
ALTER TABLE manifest_layer ADD FOREIGN KEY (manifest_id) REFERENCES manifest(id);
UPDATE manifest_layer AS ml SET manifest_id = (SELECT id FROM manifest WHERE hash = ml.manifest_hash);

ALTER TABLE manifest_layer ADD COLUMN layer_id bigint;
ALTER TABLE manifest_layer ADD FOREIGN KEY (layer_id) REFERENCES layer(id);
UPDATE manifest_layer AS ml SET layer_id = (SELECT id FROM layer WHERE hash = ml.layer_hash);

ALTER TABLE package_scanartifact ADD COLUMN layer_id bigint;
ALTER TABLE package_scanartifact ADD FOREIGN KEY (layer_id) REFERENCES layer(id);
UPDATE package_scanartifact AS r SET layer_id = (SELECT id FROM layer WHERE hash = r.layer_hash);

ALTER TABLE repo_scanartifact ADD COLUMN layer_id bigint;
ALTER TABLE repo_scanartifact ADD FOREIGN KEY (layer_id) REFERENCES layer(id);
UPDATE repo_scanartifact AS r SET layer_id = (SELECT id FROM layer WHERE hash = r.layer_hash);

ALTER TABLE scanned_layer ADD COLUMN layer_id bigint;
ALTER TABLE scanned_layer ADD FOREIGN KEY (layer_id) REFERENCES layer(id);
UPDATE scanned_layer AS r SET layer_id = (SELECT id FROM layer WHERE hash = r.layer_hash);

ALTER TABLE scanned_manifest ADD COLUMN manifest_id bigint;
ALTER TABLE scanned_manifest ADD FOREIGN KEY (manifest_id) REFERENCES manifest(id);
UPDATE scanned_manifest AS r SET manifest_id = (SELECT id FROM manifest WHERE hash = r.manifest_hash);

/* next for each table with with a manifest or layer hash column
   - drop the string column
   - optionally (re)create indexes */
ALTER TABLE dist_scanartifact DROP COLUMN layer_hash;
ALTER TABLE dist_scanartifact ADD PRIMARY KEY (layer_id, scanner_id, dist_id);

ALTER TABLE indexreport DROP COLUMN manifest_hash;
ALTER TABLE indexreport ADD PRIMARY KEY (manifest_id);

ALTER TABLE manifest_index DROP COLUMN manifest_hash;
CREATE INDEX ON manifest_index(manifest_id, package_id, dist_id, repo_id);

ALTER TABLE manifest_layer DROP COLUMN manifest_hash;
ALTER TABLE manifest_layer DROP COLUMN layer_hash;
ALTER TABLE manifest_layer ADD PRIMARY KEY (manifest_id, layer_id, i);

ALTER TABLE package_scanartifact DROP COLUMN layer_hash;
ALTER TABLE package_scanartifact ADD PRIMARY KEY (layer_id, package_id, source_id, scanner_id, package_db, repository_hint);

ALTER TABLE repo_scanartifact DROP COLUMN layer_hash;
ALTER TABLE repo_scanartifact ADD PRIMARY KEY (layer_id, repo_id, scanner_id);

ALTER TABLE scanned_layer DROP COLUMN layer_hash;
ALTER TABLE scanned_layer ADD PRIMARY KEY (layer_id, scanner_id);

ALTER TABLE scanned_manifest DROP COLUMN manifest_hash;
ALTER TABLE scanned_manifest ADD PRIMARY KEY (manifest_id, scanner_id)
