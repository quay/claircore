// # Indexer Schema
//
//	CREATE EXTENSION IF NOT EXISTS "uuid-ossp" WITH SCHEMA public;
//
//	COMMENT ON EXTENSION "uuid-ossp" IS 'generate universally unique identifiers (UUIDs)';
//
//	CREATE TYPE public.versionrange AS RANGE (
//	    subtype = integer[],
//	    multirange_type_name = public.versionmultirange
//	);
//
//	CREATE TABLE public.dist (
//	    id bigint NOT NULL,
//	    name text DEFAULT ''::text NOT NULL,
//	    did text DEFAULT ''::text NOT NULL,
//	    version text DEFAULT ''::text NOT NULL,
//	    version_code_name text DEFAULT ''::text NOT NULL,
//	    version_id text DEFAULT ''::text NOT NULL,
//	    arch text DEFAULT ''::text NOT NULL,
//	    cpe text DEFAULT ''::text NOT NULL,
//	    pretty_name text DEFAULT ''::text NOT NULL
//	);
//
//	CREATE SEQUENCE public.dist_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.dist_id_seq OWNED BY public.dist.id;
//
//	CREATE TABLE public.dist_scanartifact (
//	    dist_id bigint NOT NULL,
//	    scanner_id bigint NOT NULL,
//	    layer_id bigint NOT NULL
//	);
//
//	CREATE TABLE public.file (
//	    id bigint NOT NULL,
//	    path text NOT NULL,
//	    kind text NOT NULL
//	);
//
//	CREATE SEQUENCE public.file_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.file_id_seq OWNED BY public.file.id;
//
//	CREATE TABLE public.file_scanartifact (
//	    file_id bigint NOT NULL,
//	    scanner_id bigint NOT NULL,
//	    layer_id bigint NOT NULL
//	);
//
//	CREATE TABLE public.indexreport (
//	    state text,
//	    scan_result jsonb,
//	    manifest_id bigint NOT NULL
//	);
//
//	CREATE TABLE public.layer (
//	    hash text NOT NULL,
//	    id bigint NOT NULL
//	);
//
//	CREATE SEQUENCE public.layer_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.layer_id_seq OWNED BY public.layer.id;
//
//	CREATE TABLE public.libindex_migrations (
//	    version integer NOT NULL
//	);
//
//	CREATE TABLE public.manifest (
//	    hash text NOT NULL,
//	    id bigint NOT NULL
//	);
//
//	CREATE SEQUENCE public.manifest_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.manifest_id_seq OWNED BY public.manifest.id;
//
//	CREATE TABLE public.manifest_index (
//	    id bigint NOT NULL,
//	    package_id bigint NOT NULL,
//	    dist_id bigint,
//	    repo_id bigint,
//	    manifest_id bigint
//	);
//
//	CREATE SEQUENCE public.manifest_index_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.manifest_index_id_seq OWNED BY public.manifest_index.id;
//
//	CREATE TABLE public.manifest_layer (
//	    i bigint NOT NULL,
//	    manifest_id bigint NOT NULL,
//	    layer_id bigint NOT NULL
//	);
//
//	CREATE TABLE public.package (
//	    id bigint NOT NULL,
//	    name text NOT NULL,
//	    kind text DEFAULT ''::text NOT NULL,
//	    version text DEFAULT ''::text NOT NULL,
//	    norm_kind text,
//	    norm_version integer[],
//	    module text DEFAULT ''::text NOT NULL,
//	    arch text DEFAULT ''::text NOT NULL
//	);
//
//	CREATE SEQUENCE public.package_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.package_id_seq OWNED BY public.package.id;
//
//	CREATE TABLE public.package_scanartifact (
//	    package_id bigint NOT NULL,
//	    source_id bigint NOT NULL,
//	    scanner_id bigint NOT NULL,
//	    package_db text NOT NULL,
//	    repository_hint text NOT NULL,
//	    layer_id bigint NOT NULL,
//	    filepath text
//	);
//
//	CREATE TABLE public.repo (
//	    id bigint NOT NULL,
//	    name text NOT NULL,
//	    key text DEFAULT ''::text,
//	    uri text DEFAULT ''::text,
//	    cpe text DEFAULT ''::text
//	);
//
//	CREATE SEQUENCE public.repo_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.repo_id_seq OWNED BY public.repo.id;
//
//	CREATE TABLE public.repo_scanartifact (
//	    repo_id bigint NOT NULL,
//	    scanner_id bigint NOT NULL,
//	    layer_id bigint NOT NULL
//	);
//
//	CREATE TABLE public.scanned_layer (
//	    scanner_id bigint NOT NULL,
//	    layer_id bigint NOT NULL
//	);
//
//	CREATE TABLE public.scanned_manifest (
//	    scanner_id bigint NOT NULL,
//	    manifest_id bigint NOT NULL
//	);
//
//	CREATE TABLE public.scanner (
//	    id bigint NOT NULL,
//	    name text NOT NULL,
//	    version text NOT NULL,
//	    kind text NOT NULL
//	);
//
//	CREATE SEQUENCE public.scanner_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.scanner_id_seq OWNED BY public.scanner.id;
//
//	CREATE TABLE public.scannerlist (
//	    id bigint NOT NULL,
//	    manifest_hash text,
//	    scanner_id bigint
//	);
//
//	CREATE SEQUENCE public.scannerlist_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.scannerlist_id_seq OWNED BY public.scannerlist.id;
//
//	ALTER TABLE ONLY public.dist ALTER COLUMN id SET DEFAULT nextval('public.dist_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.file ALTER COLUMN id SET DEFAULT nextval('public.file_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.layer ALTER COLUMN id SET DEFAULT nextval('public.layer_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.manifest ALTER COLUMN id SET DEFAULT nextval('public.manifest_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.manifest_index ALTER COLUMN id SET DEFAULT nextval('public.manifest_index_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.package ALTER COLUMN id SET DEFAULT nextval('public.package_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.repo ALTER COLUMN id SET DEFAULT nextval('public.repo_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.scanner ALTER COLUMN id SET DEFAULT nextval('public.scanner_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.scannerlist ALTER COLUMN id SET DEFAULT nextval('public.scannerlist_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.dist
//	    ADD CONSTRAINT dist_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.dist_scanartifact
//	    ADD CONSTRAINT dist_scanartifact_pkey PRIMARY KEY (layer_id, scanner_id, dist_id);
//
//	ALTER TABLE ONLY public.file
//	    ADD CONSTRAINT file_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.file_scanartifact
//	    ADD CONSTRAINT file_scanartifact_pkey PRIMARY KEY (layer_id, scanner_id, file_id);
//
//	ALTER TABLE ONLY public.indexreport
//	    ADD CONSTRAINT indexreport_pkey PRIMARY KEY (manifest_id);
//
//	ALTER TABLE ONLY public.layer
//	    ADD CONSTRAINT layer_hash_unique UNIQUE (hash);
//
//	ALTER TABLE ONLY public.layer
//	    ADD CONSTRAINT layer_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.libindex_migrations
//	    ADD CONSTRAINT libindex_migrations_pkey PRIMARY KEY (version);
//
//	ALTER TABLE ONLY public.manifest
//	    ADD CONSTRAINT manifest_hash_unique UNIQUE (hash);
//
//	ALTER TABLE ONLY public.manifest_index
//	    ADD CONSTRAINT manifest_index_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.manifest_layer
//	    ADD CONSTRAINT manifest_layer_pkey PRIMARY KEY (manifest_id, layer_id, i);
//
//	ALTER TABLE ONLY public.manifest
//	    ADD CONSTRAINT manifest_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.package
//	    ADD CONSTRAINT package_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.package_scanartifact
//	    ADD CONSTRAINT package_scanartifact_pkey PRIMARY KEY (layer_id, package_id, source_id, scanner_id, package_db, repository_hint);
//
//	ALTER TABLE ONLY public.repo
//	    ADD CONSTRAINT repo_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.repo_scanartifact
//	    ADD CONSTRAINT repo_scanartifact_pkey PRIMARY KEY (layer_id, repo_id, scanner_id);
//
//	ALTER TABLE ONLY public.scanned_layer
//	    ADD CONSTRAINT scanned_layer_pkey PRIMARY KEY (layer_id, scanner_id);
//
//	ALTER TABLE ONLY public.scanned_manifest
//	    ADD CONSTRAINT scanned_manifest_pkey PRIMARY KEY (manifest_id, scanner_id);
//
//	ALTER TABLE ONLY public.scanner
//	    ADD CONSTRAINT scanner_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.scannerlist
//	    ADD CONSTRAINT scannerlist_pkey PRIMARY KEY (id);
//
//	CREATE UNIQUE INDEX dist_unique_idx ON public.dist USING btree (name, did, version, version_code_name, version_id, arch, cpe, pretty_name);
//
//	CREATE UNIQUE INDEX file_unique_idx ON public.file USING btree (path, kind);
//
//	CREATE INDEX idx_manifest_index_manifest_id ON public.manifest_index USING btree (manifest_id);
//
//	CREATE INDEX idx_manifest_layer_layer_id ON public.manifest_layer USING btree (layer_id);
//
//	CREATE INDEX layer_hash_idx ON public.layer USING btree (hash);
//
//	CREATE INDEX manifest_hash_idx ON public.manifest USING btree (hash);
//
//	CREATE UNIQUE INDEX manifest_index_unique ON public.manifest_index USING btree (package_id, COALESCE(dist_id, (0)::bigint), COALESCE(repo_id, (0)::bigint), manifest_id);
//
//	CREATE UNIQUE INDEX package_unique_idx ON public.package USING btree (name, version, kind, module, arch);
//
//	CREATE UNIQUE INDEX repo_unique_idx ON public.repo USING btree (name, key, uri);
//
//	CREATE UNIQUE INDEX scanner_unique_idx ON public.scanner USING btree (name, kind, version);
//
//	CREATE INDEX scannerlist_manifest_hash_idx ON public.scannerlist USING btree (manifest_hash);
//
//	ALTER TABLE ONLY public.dist_scanartifact
//	    ADD CONSTRAINT dist_scanartifact_dist_id_fkey FOREIGN KEY (dist_id) REFERENCES public.dist(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.dist_scanartifact
//	    ADD CONSTRAINT dist_scanartifact_layer_id_fkey FOREIGN KEY (layer_id) REFERENCES public.layer(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.dist_scanartifact
//	    ADD CONSTRAINT dist_scanartifact_scanner_id_fkey FOREIGN KEY (scanner_id) REFERENCES public.scanner(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.file_scanartifact
//	    ADD CONSTRAINT file_scanartifact_file_id_fkey FOREIGN KEY (file_id) REFERENCES public.file(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.file_scanartifact
//	    ADD CONSTRAINT file_scanartifact_layer_id_fkey FOREIGN KEY (layer_id) REFERENCES public.layer(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.file_scanartifact
//	    ADD CONSTRAINT file_scanartifact_scanner_id_fkey FOREIGN KEY (scanner_id) REFERENCES public.scanner(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.indexreport
//	    ADD CONSTRAINT indexreport_manifest_id_fkey FOREIGN KEY (manifest_id) REFERENCES public.manifest(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.manifest_index
//	    ADD CONSTRAINT manifest_index_dist_id_fkey FOREIGN KEY (dist_id) REFERENCES public.dist(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.manifest_index
//	    ADD CONSTRAINT manifest_index_manifest_id_fkey FOREIGN KEY (manifest_id) REFERENCES public.manifest(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.manifest_index
//	    ADD CONSTRAINT manifest_index_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.package(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.manifest_index
//	    ADD CONSTRAINT manifest_index_repo_id_fkey FOREIGN KEY (repo_id) REFERENCES public.repo(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.manifest_layer
//	    ADD CONSTRAINT manifest_layer_layer_id_fkey FOREIGN KEY (layer_id) REFERENCES public.layer(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.manifest_layer
//	    ADD CONSTRAINT manifest_layer_manifest_id_fkey FOREIGN KEY (manifest_id) REFERENCES public.manifest(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.package_scanartifact
//	    ADD CONSTRAINT package_scanartifact_layer_id_fkey FOREIGN KEY (layer_id) REFERENCES public.layer(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.package_scanartifact
//	    ADD CONSTRAINT package_scanartifact_package_id_fkey FOREIGN KEY (package_id) REFERENCES public.package(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.package_scanartifact
//	    ADD CONSTRAINT package_scanartifact_scanner_id_fkey FOREIGN KEY (scanner_id) REFERENCES public.scanner(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.package_scanartifact
//	    ADD CONSTRAINT package_scanartifact_source_id_fkey FOREIGN KEY (package_id) REFERENCES public.package(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.repo_scanartifact
//	    ADD CONSTRAINT repo_scanartifact_layer_id_fkey FOREIGN KEY (layer_id) REFERENCES public.layer(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.repo_scanartifact
//	    ADD CONSTRAINT repo_scanartifact_repo_id_fkey FOREIGN KEY (repo_id) REFERENCES public.repo(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.repo_scanartifact
//	    ADD CONSTRAINT repo_scanartifact_scanner_id_fkey FOREIGN KEY (scanner_id) REFERENCES public.scanner(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.scanned_layer
//	    ADD CONSTRAINT scanned_layer_layer_id_fkey FOREIGN KEY (layer_id) REFERENCES public.layer(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.scanned_layer
//	    ADD CONSTRAINT scanned_layer_scanner_id_fkey FOREIGN KEY (scanner_id) REFERENCES public.scanner(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.scanned_manifest
//	    ADD CONSTRAINT scanned_manifest_manifest_id_fkey FOREIGN KEY (manifest_id) REFERENCES public.manifest(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.scanned_manifest
//	    ADD CONSTRAINT scanned_manifest_scanner_id_fkey FOREIGN KEY (scanner_id) REFERENCES public.scanner(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.scannerlist
//	    ADD CONSTRAINT scannerlist_scanner_id_fkey FOREIGN KEY (scanner_id) REFERENCES public.scanner(id) ON DELETE CASCADE;
package migrations
