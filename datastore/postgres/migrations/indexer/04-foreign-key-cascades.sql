-- Add CASADEs on all foreign-key relations.
-- This makes deleting manifests and layers much simpler.
ALTER TABLE indexreport
	DROP CONSTRAINT indexreport_manifest_id_fkey;
ALTER TABLE indexreport
	ADD CONSTRAINT indexreport_manifest_id_fkey
	FOREIGN KEY (manifest_id)
	REFERENCES manifest(id)
	ON DELETE CASCADE;

ALTER TABLE dist_scanartifact
	DROP CONSTRAINT dist_scanartifact_dist_id_fkey;
ALTER TABLE dist_scanartifact
	ADD CONSTRAINT dist_scanartifact_dist_id_fkey
	FOREIGN KEY (dist_id)
	REFERENCES dist(id)
	ON DELETE CASCADE;
ALTER TABLE dist_scanartifact
	DROP CONSTRAINT dist_scanartifact_layer_id_fkey;
ALTER TABLE dist_scanartifact
	ADD CONSTRAINT dist_scanartifact_layer_id_fkey
	FOREIGN KEY (layer_id)
	REFERENCES layer(id)
	ON DELETE CASCADE;
ALTER TABLE dist_scanartifact
	DROP CONSTRAINT dist_scanartifact_scanner_id_fkey;
ALTER TABLE dist_scanartifact
	ADD CONSTRAINT dist_scanartifact_scanner_id_fkey
	FOREIGN KEY (scanner_id)
	REFERENCES scanner(id)
	ON DELETE CASCADE;

ALTER TABLE manifest_index
	DROP CONSTRAINT manifest_index_dist_id_fkey;
ALTER TABLE manifest_index
	ADD CONSTRAINT manifest_index_dist_id_fkey
	FOREIGN KEY (dist_id)
	REFERENCES dist(id)
	ON DELETE CASCADE;
ALTER TABLE manifest_index
	DROP CONSTRAINT manifest_index_manifest_id_fkey;
ALTER TABLE manifest_index
	ADD CONSTRAINT manifest_index_manifest_id_fkey
	FOREIGN KEY (manifest_id)
	REFERENCES manifest(id)
	ON DELETE CASCADE;
ALTER TABLE manifest_index
	DROP CONSTRAINT manifest_index_package_id_fkey;
ALTER TABLE manifest_index
	ADD CONSTRAINT manifest_index_package_id_fkey
	FOREIGN KEY (package_id)
	REFERENCES package(id)
	ON DELETE CASCADE;
ALTER TABLE manifest_index
	DROP CONSTRAINT manifest_index_repo_id_fkey;
ALTER TABLE manifest_index
	ADD CONSTRAINT manifest_index_repo_id_fkey
	FOREIGN KEY (repo_id)
	REFERENCES repo(id)
	ON DELETE CASCADE;

ALTER TABLE manifest_layer
	DROP CONSTRAINT manifest_layer_layer_id_fkey;
ALTER TABLE manifest_layer
	ADD CONSTRAINT manifest_layer_layer_id_fkey
	FOREIGN KEY (layer_id)
	REFERENCES layer(id)
	ON DELETE CASCADE;
ALTER TABLE manifest_layer
	DROP CONSTRAINT manifest_layer_manifest_id_fkey;
ALTER TABLE manifest_layer
	ADD CONSTRAINT manifest_layer_manifest_id_fkey
	FOREIGN KEY (manifest_id)
	REFERENCES manifest(id)
	ON DELETE CASCADE;

ALTER TABLE package_scanartifact
	DROP CONSTRAINT package_scanartifact_layer_id_fkey;
ALTER TABLE package_scanartifact
	ADD CONSTRAINT package_scanartifact_layer_id_fkey
	FOREIGN KEY (layer_id)
	REFERENCES layer(id)
	ON DELETE CASCADE;
ALTER TABLE package_scanartifact
	DROP CONSTRAINT package_scanartifact_package_id_fkey;
ALTER TABLE package_scanartifact
	ADD CONSTRAINT package_scanartifact_package_id_fkey
	FOREIGN KEY (package_id)
	REFERENCES package(id)
	ON DELETE CASCADE;
ALTER TABLE package_scanartifact
	DROP CONSTRAINT package_scanartifact_scanner_id_fkey;
ALTER TABLE package_scanartifact
	ADD CONSTRAINT package_scanartifact_scanner_id_fkey
	FOREIGN KEY (scanner_id)
	REFERENCES scanner(id)
	ON DELETE CASCADE;
ALTER TABLE package_scanartifact
	DROP CONSTRAINT package_scanartifact_source_id_fkey;
ALTER TABLE package_scanartifact
	ADD CONSTRAINT package_scanartifact_source_id_fkey
	FOREIGN KEY (package_id)
	REFERENCES package(id)
	ON DELETE CASCADE;

ALTER TABLE repo_scanartifact
	DROP CONSTRAINT repo_scanartifact_layer_id_fkey;
ALTER TABLE repo_scanartifact
	ADD CONSTRAINT repo_scanartifact_layer_id_fkey
	FOREIGN KEY (layer_id)
	REFERENCES layer(id)
	ON DELETE CASCADE;
ALTER TABLE repo_scanartifact
	DROP CONSTRAINT repo_scanartifact_repo_id_fkey;
ALTER TABLE repo_scanartifact
	ADD CONSTRAINT repo_scanartifact_repo_id_fkey
	FOREIGN KEY (repo_id)
	REFERENCES repo(id)
	ON DELETE CASCADE;
ALTER TABLE repo_scanartifact
	DROP CONSTRAINT repo_scanartifact_scanner_id_fkey;
ALTER TABLE repo_scanartifact
	ADD CONSTRAINT repo_scanartifact_scanner_id_fkey
	FOREIGN KEY (scanner_id)
	REFERENCES scanner(id)
	ON DELETE CASCADE;

ALTER TABLE scanned_layer
	DROP CONSTRAINT scanned_layer_layer_id_fkey;
ALTER TABLE scanned_layer
	ADD CONSTRAINT scanned_layer_layer_id_fkey
	FOREIGN KEY (layer_id)
	REFERENCES layer(id)
	ON DELETE CASCADE;
ALTER TABLE scanned_layer
	DROP CONSTRAINT scanned_layer_scanner_id_fkey;
ALTER TABLE scanned_layer
	ADD CONSTRAINT scanned_layer_scanner_id_fkey
	FOREIGN KEY (scanner_id)
	REFERENCES scanner(id)
	ON DELETE CASCADE;

ALTER TABLE scanned_manifest
	DROP CONSTRAINT scanned_manifest_manifest_id_fkey;
ALTER TABLE scanned_manifest
	ADD CONSTRAINT scanned_manifest_manifest_id_fkey
	FOREIGN KEY (manifest_id)
	REFERENCES manifest(id)
	ON DELETE CASCADE;
ALTER TABLE scanned_manifest
	DROP CONSTRAINT scanned_manifest_scanner_id_fkey;
ALTER TABLE scanned_manifest
	ADD CONSTRAINT scanned_manifest_scanner_id_fkey
	FOREIGN KEY (scanner_id)
	REFERENCES scanner(id)
	ON DELETE CASCADE;

ALTER TABLE scannerlist
	DROP CONSTRAINT scannerlist_scanner_id_fkey;
ALTER TABLE scannerlist
	ADD CONSTRAINT scannerlist_scanner_id_fkey
	FOREIGN KEY (scanner_id)
	REFERENCES scanner(id)
	ON DELETE CASCADE;

