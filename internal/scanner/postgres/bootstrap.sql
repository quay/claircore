-- Distribution
--- a unique distribution discovered by a scanner
CREATE TABLE dist (
    id SERIAL PRIMARY KEY,
    name text,
    version text,
    version_code_name text,
    version_id text,
    arch text,
    unique(name, version, version_code_name, version_id, arch)
);
CREATE INDEX dist_unique_idx ON dist (name, version, version_code_name, version_id, arch);
CREATE INDEX dist_name_idx ON dist (name);
CREATE INDEX dist_version_idx ON dist (version);
CREATE INDEX dist_version_code_name_idx ON dist (version_code_name);
CREATE INDEX dist_version_id_idx ON dist (version_id);
CREATE INDEX dist_arch_idx ON dist (arch);

--- Package
--- a unique package discovered by a scanner
CREATE TABLE package (
    id SERIAL PRIMARY KEY,
    name text NOT NULL,
    kind text NOT NULL,
    version text NOT NULL,
    unique(name, version, kind)
);
CREATE INDEX package_unique_idx ON package (name, version, kind);
CREATE INDEX package_name_idx ON package (name);
CREATE INDEX package_version_idx ON package (version);
CREATE INDEX package_kind_idx ON package (kind);

--- Repository
--- a unique package repository discovered by a scanner
CREATE TABLE repository (
    id SERIAL PRIMARY KEY,
    name text NOT NULL,
    key text,
    uri text
);
CREATE INDEX repo_unique_idx ON repository (name, key, uri);

--- Scanner
--- a unique versioned scanner which is responsible
--- for finding packages and distributions in a layer
CREATE TABLE scanner (
    id SERIAL PRIMARY KEY,
    name text NOT NULL,
    version text NOT NULL,
    kind text NOT NULL,
    unique(name, version, kind)
);
CREATE INDEX scanner_unique_idx ON scanner (name, kind, version);
CREATE INDEX scanner_name_idx ON scanner (name);
CREATE INDEX scanner_kind_idx ON scanner (kind);
CREATE INDEX scanner_version_idx ON scanner (version);

--- ScannerList
--- a relation informing us if a manifest hash has 
--- been scanned by a particular scanner
CREATE TABLE scannerlist (
    id SERIAL PRIMARY KEY,
    manifest_hash text,
    scanner_id int REFERENCES scanner(id)
);
CREATE INDEX scannerlist_manifest_hash_idx ON scannerlist (manifest_hash);

--- PackageScanArtifact
--- A relation linking discovered packages with the 
--- layer hash it was found
CREATE TABLE package_scanartifact (
    id SERIAL PRIMARY KEY,
    layer_hash text,
    package_id int REFERENCES package(id),
    source_id int REFERENCES package(id),
    db_path text,
    repository_hint text,
    scanner_id int REFERENCES scanner(id),
    unique(layer_hash, package_id, source_id, scanner_id)
);
CREATE INDEX package_scanartifact_unique_idx ON package_scanartifact (layer_hash, package_id, source_id, scanner_id);
CREATE INDEX package_scanartifact_layer_hash_idx ON package_scanartifact (layer_hash);
CREATE INDEX package_scanartifact_layer_hash_scanner_id_idx ON package_scanartifact (layer_hash, scanner_id);

--- DistributionScanArtifact
--- A relation linking discovered distributions to a layer
CREATE TABLE dist_scanartifact (
    id SERIAL PRIMARY KEY,
    layer_hash text,
    dist_id int REFERENCES dist(id),
    scanner_id int REFERENCES scanner(id)
);
CREATE INDEX dist_scanartifact_unique_idx ON dist_scanartifact (layer_hash, dist_id, scanner_id);
CREATE INDEX dist_scanartifact_layer_hash_idx ON dist_scanartifact (layer_hash);
CREATE INDEX dist_scanartifact_layer_hash_scanner_id_idx ON dist_scanartifact (layer_hash, scanner_id);

--- RepositoryScanArtifact
--- A relation linking discovered distributions to a layer
CREATE TABLE repo_scanartifact (
    id SERIAL PRIMARY KEY,
    layer_hash text,
    repo_id int REFERENCES repository(id),
    scanner_id int REFERENCES scanner(id)
);
CREATE INDEX repo_scanartifact_unique_idx ON repo_scanartifact (layer_hash, repo_id, scanner_id);
CREATE INDEX repo_scanartifact_layer_hash_idx ON repo_scanartifact (layer_hash);
CREATE INDEX repo_scanartifact_layer_hash_scanner_id_idx ON repo_scanartifact (layer_hash, scanner_id);

--- ScanReport
CREATE TABLE scanreport (
    manifest_hash text PRIMARY KEY,
    state text,
    scan_result jsonb
);
CREATE INDEX scanreport_manifest_hash_idx ON scanreport (manifest_hash);
