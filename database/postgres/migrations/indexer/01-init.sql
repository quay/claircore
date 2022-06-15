--- Layer
--- an identity table consisting of a content addressable layer hash
CREATE TABLE IF NOT EXISTS layer (
	hash text PRIMARY KEY
);

--- Manifest
--- an identity table consisting of a content addressable manifest hash
CREATE TABLE IF NOT EXISTS manifest (
	hash text PRIMARY KEY
);

--- ManifestLayer
--- a many to many link table identifying the layers which comprise a manifest
--- and the layer's ordering within a manifest
CREATE TABLE IF NOT EXISTS manifest_layer (
	manifest_hash text REFERENCES manifest(hash),
	layer_hash text REFERENCES layer(hash),
	i bigint,
	PRIMARY KEY(manifest_hash, layer_hash, i)
);

--- Scanner
--- a unique versioned scanner which is responsible
--- for finding packages and distributions in a layer
CREATE TABLE IF NOT EXISTS scanner (
	id BIGSERIAL PRIMARY KEY,
	name text NOT NULL,
	version text NOT NULL,
	kind text NOT NULL
);
CREATE UNIQUE INDEX IF NOT EXISTS scanner_unique_idx ON scanner (name, kind, version);

--- ScannedManifest
--- a relation to identify if a manifest was successfully scanned by a particular
--- scanner
CREATE TABLE IF NOT EXISTS scanned_manifest (
	manifest_hash text REFERENCES manifest(hash),
	scanner_id bigint REFERENCES scanner(id),
	PRIMARY KEY(manifest_hash, scanner_id)
);

--- ScannedLayer
--- a relation to identify if a layer was successfully scanned by a particular scanner
CREATE TABLE IF NOT EXISTS scanned_layer (
	layer_hash text REFERENCES layer(hash),
	scanner_id bigint REFERENCES scanner(id),
	PRIMARY KEY(layer_hash, scanner_id)
);

--- ScannerList
--- a relation informing us if a manifest hash has
--- been scanned by a particular scanner
CREATE TABLE IF NOT EXISTS scannerlist (
	id BIGSERIAL PRIMARY KEY,
	manifest_hash text,
	scanner_id bigint REFERENCES scanner(id)
);
CREATE INDEX IF NOT EXISTS scannerlist_manifest_hash_idx ON scannerlist (manifest_hash);

--- IndexReport
--- the jsonb serialized result of a scan for a particular
--- manifest
CREATE TABLE IF NOT EXISTS indexreport (
	manifest_hash text PRIMARY KEY REFERENCES manifest(hash),
	state text,
	scan_result jsonb
);

-- Distribution
--- a unique distribution discovered by a scanner
CREATE TABLE IF NOT EXISTS dist (
	id BIGSERIAL PRIMARY KEY,
	name text NOT NULL DEFAULT '',
	did text NOT NULL DEFAULT '', -- os-release id field
	version text NOT NULL DEFAULT '',
	version_code_name text NOT NULL DEFAULT '',
	version_id text NOT NULL DEFAULT '',
	arch text NOT NULL DEFAULT '',
	cpe text NOT NULL DEFAULT '',
	pretty_name text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS dist_unique_idx ON dist (name, did, version, version_code_name, version_id, arch, cpe, pretty_name);

--- DistributionScanArtifact
--- A relation linking discovered distributions to a layer
CREATE TABLE IF NOT EXISTS dist_scanartifact (
	  dist_id bigint REFERENCES dist(id),
	  scanner_id bigint REFERENCES scanner(id),
	  layer_hash text REFERENCES layer(hash),
	  PRIMARY KEY(dist_id, scanner_id, layer_hash)
);
CREATE INDEX IF NOT EXISTS dist_scanartifact_lookup_idx ON dist_scanartifact(layer_hash);

--- Package
--- a unique package discovered by a scanner
CREATE TABLE IF NOT EXISTS package (
	id BIGSERIAL PRIMARY KEY,
	name text NOT NULL,
	kind text NOT NULL DEFAULT '',
	version text NOT NULL DEFAULT '',
	norm_kind text,
	norm_version integer[10],
	module text NOT NULL DEFAULT '',
	arch text NOT NULL DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS package_unique_idx ON package (name, version, kind, module, arch);

--- PackageScanArtifact
--- A relation linking discovered packages with the
--- layer hash it was found
CREATE TABLE IF NOT EXISTS package_scanartifact (
	   layer_hash text REFERENCES layer(hash),
	   package_id bigint REFERENCES package(id),
	   source_id bigint REFERENCES package(id),
	   scanner_id bigint REFERENCES scanner(id),
	   package_db text,
	   repository_hint text,
	   PRIMARY KEY(layer_hash, package_id, source_id, scanner_id, package_db, repository_hint)
);
CREATE INDEX IF NOT EXISTS package_scanartifact_lookup_idx ON package_scanartifact(layer_hash);

--- Repository
--- a unique package repository discovered by a scanner
CREATE TABLE IF NOT EXISTS repo (
	id BIGSERIAL PRIMARY KEY,
	name text NOT NULL,
	key text DEFAULT '',
	uri text DEFAULT '',
	cpe text DEFAULT ''
);
CREATE UNIQUE INDEX IF NOT EXISTS repo_unique_idx ON repo (name, key, uri);

--- RepositoryScanArtifact
--- A relation linking discovered distributions to a layer
CREATE TABLE IF NOT EXISTS repo_scanartifact (
	repo_id bigint REFERENCES repo(id),
	scanner_id bigint REFERENCES scanner(id),
	layer_hash text REFERENCES layer(hash),
	PRIMARY KEY(repo_id, scanner_id, layer_hash)
);
CREATE INDEX IF NOT EXISTS repo_scanartifact_lookup_idx ON repo_scanartifact(layer_hash);

--- ManifestIndex
--- A searchable index of a coalesced manifest's content.
--- a package id is required.
--- either a dist_id or a repo_id maybe null, but not both
CREATE TABLE IF NOT EXISTS manifest_index
(
	id            bigserial PRIMARY KEY,
	package_id    bigint NOT NULL REFERENCES package (id),
	dist_id       bigint REFERENCES dist (id),
	repo_id       bigint REFERENCES repo (id),
	manifest_hash text REFERENCES manifest (hash)
);
CREATE INDEX IF NOT EXISTS manifest_index_hash_lookup_idx ON manifest_index (manifest_hash);
CREATE UNIQUE INDEX manifest_index_unique ON manifest_index (package_id, COALESCE(dist_id, 0), COALESCE(repo_id, 0), manifest_hash);
