// # Matcher Schema
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
//	CREATE TABLE public.alias (
//	    id integer NOT NULL,
//	    namespace integer NOT NULL,
//	    name text NOT NULL
//	);
//
//	COMMENT ON TABLE public.alias IS 'Table for all known aliases of vulnerabilities in the system. All vulnerabilities should have at least one alias.';
//
//	ALTER TABLE public.alias ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
//	    SEQUENCE NAME public.alias_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1
//	);
//
//	CREATE TABLE public.alias_namespace (
//	    id integer NOT NULL,
//	    namespace text NOT NULL
//	);
//
//	COMMENT ON TABLE public.alias_namespace IS 'Contains namespaces for aliases. Usually short IDs like "CVE" or "GHSA".';
//
//	ALTER TABLE public.alias_namespace ALTER COLUMN id ADD GENERATED ALWAYS AS IDENTITY (
//	    SEQUENCE NAME public.alias_namespace_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1
//	);
//
//	CREATE TABLE public.enrichment (
//	    id bigint NOT NULL,
//	    hash_kind text,
//	    hash bytea,
//	    updater text,
//	    tags text[],
//	    data jsonb
//	);
//
//	CREATE SEQUENCE public.enrichment_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.enrichment_id_seq OWNED BY public.enrichment.id;
//
//	CREATE TABLE public.update_operation (
//	    id bigint NOT NULL,
//	    ref uuid DEFAULT public.uuid_generate_v4(),
//	    updater text NOT NULL,
//	    fingerprint text,
//	    date timestamp with time zone DEFAULT now(),
//	    kind text
//	);
//
//	CREATE MATERIALIZED VIEW public.latest_update_operations AS
//	 SELECT DISTINCT ON (updater) id,
//	    kind,
//	    updater
//	   FROM public.update_operation
//	  ORDER BY updater, id DESC
//	  WITH NO DATA;
//
//	CREATE TABLE public.uo_vuln (
//	    uo bigint NOT NULL,
//	    vuln bigint NOT NULL
//	);
//
//	CREATE TABLE public.vuln (
//	    id bigint NOT NULL,
//	    hash_kind text NOT NULL,
//	    hash bytea NOT NULL,
//	    updater text,
//	    name text,
//	    description text,
//	    issued timestamp with time zone,
//	    links text,
//	    severity text,
//	    normalized_severity text,
//	    package_name text,
//	    package_version text,
//	    package_module text,
//	    package_arch text,
//	    package_kind text,
//	    dist_id text,
//	    dist_name text,
//	    dist_version text,
//	    dist_version_code_name text,
//	    dist_version_id text,
//	    dist_arch text,
//	    dist_cpe text,
//	    dist_pretty_name text,
//	    repo_name text,
//	    repo_key text,
//	    repo_uri text,
//	    fixed_in_version text,
//	    arch_operation text,
//	    vulnerable_range public.versionrange DEFAULT public.versionrange('{}'::integer[], '{}'::integer[], '()'::text) NOT NULL,
//	    version_kind text,
//	    not_vulnerable boolean DEFAULT false NOT NULL
//	);
//
//	COMMENT ON COLUMN public.vuln.not_vulnerable IS 'Invert the meaning of the record: assert that described versions are not vulnerable.';
//
//	CREATE VIEW public.latest_vuln AS
//	 SELECT v.id,
//	    v.hash_kind,
//	    v.hash,
//	    v.updater,
//	    v.name,
//	    v.description,
//	    v.issued,
//	    v.links,
//	    v.severity,
//	    v.normalized_severity,
//	    v.package_name,
//	    v.package_version,
//	    v.package_module,
//	    v.package_arch,
//	    v.package_kind,
//	    v.dist_id,
//	    v.dist_name,
//	    v.dist_version,
//	    v.dist_version_code_name,
//	    v.dist_version_id,
//	    v.dist_arch,
//	    v.dist_cpe,
//	    v.dist_pretty_name,
//	    v.repo_name,
//	    v.repo_key,
//	    v.repo_uri,
//	    v.fixed_in_version,
//	    v.arch_operation,
//	    v.vulnerable_range,
//	    v.version_kind
//	   FROM ((( SELECT DISTINCT ON (update_operation.updater) update_operation.id
//	           FROM public.update_operation
//	          ORDER BY update_operation.updater, update_operation.id DESC) uo
//	     JOIN public.uo_vuln ON ((uo_vuln.uo = uo.id)))
//	     JOIN public.vuln v ON ((uo_vuln.vuln = v.id)));
//
//	CREATE TABLE public.libvuln_migrations (
//	    version integer NOT NULL
//	);
//
//	CREATE TABLE public.uo_enrich (
//	    uo bigint NOT NULL,
//	    enrich bigint NOT NULL,
//	    updater text,
//	    fingerprint text,
//	    date timestamp with time zone
//	);
//
//	CREATE SEQUENCE public.update_operation_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.update_operation_id_seq OWNED BY public.update_operation.id;
//
//	CREATE TABLE public.updater_status (
//	    updater_name text NOT NULL,
//	    last_attempt timestamp with time zone DEFAULT now(),
//	    last_success timestamp with time zone,
//	    last_run_succeeded boolean,
//	    last_attempt_fingerprint text,
//	    last_error text
//	);
//
//	CREATE SEQUENCE public.vuln_id_seq
//	    START WITH 1
//	    INCREMENT BY 1
//	    NO MINVALUE
//	    NO MAXVALUE
//	    CACHE 1;
//
//	ALTER SEQUENCE public.vuln_id_seq OWNED BY public.vuln.id;
//
//	CREATE TABLE public.vulnerability_alias (
//	    vulnerability bigint NOT NULL,
//	    alias integer NOT NULL
//	);
//
//	COMMENT ON TABLE public.vulnerability_alias IS 'Pivot table linking vulnerabilities to aliases.';
//
//	CREATE TABLE public.vulnerability_self (
//	    vulnerability bigint NOT NULL,
//	    self integer NOT NULL
//	);
//
//	COMMENT ON TABLE public.vulnerability_self IS 'Indicates the "self" alias for a vulnerability.';
//
//	ALTER TABLE ONLY public.enrichment ALTER COLUMN id SET DEFAULT nextval('public.enrichment_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.update_operation ALTER COLUMN id SET DEFAULT nextval('public.update_operation_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.vuln ALTER COLUMN id SET DEFAULT nextval('public.vuln_id_seq'::regclass);
//
//	ALTER TABLE ONLY public.alias
//	    ADD CONSTRAINT alias_namespace_name_key UNIQUE (namespace, name);
//
//	ALTER TABLE ONLY public.alias_namespace
//	    ADD CONSTRAINT alias_namespace_namespace_key UNIQUE (namespace);
//
//	ALTER TABLE ONLY public.alias_namespace
//	    ADD CONSTRAINT alias_namespace_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.alias
//	    ADD CONSTRAINT alias_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.enrichment
//	    ADD CONSTRAINT enrichment_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.libvuln_migrations
//	    ADD CONSTRAINT libvuln_migrations_pkey PRIMARY KEY (version);
//
//	ALTER TABLE ONLY public.uo_enrich
//	    ADD CONSTRAINT uo_enrich_pkey PRIMARY KEY (uo, enrich);
//
//	ALTER TABLE ONLY public.uo_vuln
//	    ADD CONSTRAINT uo_vuln_pkey PRIMARY KEY (uo, vuln);
//
//	ALTER TABLE ONLY public.update_operation
//	    ADD CONSTRAINT update_operation_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.update_operation
//	    ADD CONSTRAINT update_operation_ref_key UNIQUE (ref);
//
//	ALTER TABLE ONLY public.updater_status
//	    ADD CONSTRAINT updater_status_pkey PRIMARY KEY (updater_name);
//
//	ALTER TABLE ONLY public.vuln
//	    ADD CONSTRAINT vuln_hash_kind_hash_key UNIQUE (hash_kind, hash);
//
//	ALTER TABLE ONLY public.vuln
//	    ADD CONSTRAINT vuln_pkey PRIMARY KEY (id);
//
//	ALTER TABLE ONLY public.vulnerability_alias
//	    ADD CONSTRAINT vulnerability_alias_pkey PRIMARY KEY (vulnerability, alias);
//
//	ALTER TABLE ONLY public.vulnerability_self
//	    ADD CONSTRAINT vulnerability_self_pkey PRIMARY KEY (vulnerability);
//
//	CREATE UNIQUE INDEX enrichment_hash_kind_hash_idx ON public.enrichment USING btree (hash_kind, hash);
//
//	CREATE INDEX enrichment_tags_idx ON public.enrichment USING gin (tags);
//
//	CREATE INDEX enrichment_updater_idx ON public.enrichment USING btree (updater);
//
//	CREATE UNIQUE INDEX idx_updater_uniq ON public.latest_update_operations USING btree (updater);
//
//	CREATE INDEX uo_enrich_enrich_idx ON public.uo_enrich USING btree (enrich);
//
//	CREATE INDEX uo_enrich_uo_idx ON public.uo_enrich USING btree (uo);
//
//	CREATE INDEX uo_updater_idx ON public.update_operation USING btree (updater);
//
//	CREATE INDEX uo_vuln_uo_idx ON public.uo_vuln USING btree (uo);
//
//	CREATE INDEX uo_vuln_vuln_idx ON public.uo_vuln USING btree (vuln);
//
//	CREATE INDEX update_operation_kind_idx ON public.update_operation USING btree (kind);
//
//	CREATE INDEX update_operation_updater_idx ON public.update_operation USING btree (updater);
//
//	CREATE INDEX vuln_lookup_idx ON public.vuln USING btree (package_name, dist_id, dist_name, dist_pretty_name, dist_version, dist_version_id, package_module, dist_version_code_name, repo_name, dist_arch, dist_cpe, repo_key, repo_uri);
//
//	CREATE INDEX vuln_updater_idx ON public.vuln USING btree (updater);
//
//	ALTER TABLE ONLY public.alias
//	    ADD CONSTRAINT alias_namespace_fkey FOREIGN KEY (namespace) REFERENCES public.alias_namespace(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.uo_enrich
//	    ADD CONSTRAINT uo_enrich_enrich_fkey FOREIGN KEY (enrich) REFERENCES public.enrichment(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.uo_enrich
//	    ADD CONSTRAINT uo_enrich_uo_fkey FOREIGN KEY (uo) REFERENCES public.update_operation(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.uo_vuln
//	    ADD CONSTRAINT uo_vuln_uo_fkey FOREIGN KEY (uo) REFERENCES public.update_operation(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.uo_vuln
//	    ADD CONSTRAINT uo_vuln_vuln_fkey FOREIGN KEY (vuln) REFERENCES public.vuln(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.vulnerability_alias
//	    ADD CONSTRAINT vulnerability_alias_alias_fkey FOREIGN KEY (alias) REFERENCES public.alias(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.vulnerability_alias
//	    ADD CONSTRAINT vulnerability_alias_vulnerability_fkey FOREIGN KEY (vulnerability) REFERENCES public.vuln(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.vulnerability_self
//	    ADD CONSTRAINT vulnerability_self_self_fkey FOREIGN KEY (self) REFERENCES public.alias(id) ON DELETE CASCADE;
//
//	ALTER TABLE ONLY public.vulnerability_self
//	    ADD CONSTRAINT vulnerability_self_vulnerability_fkey FOREIGN KEY (vulnerability) REFERENCES public.vuln(id) ON DELETE CASCADE;
package migrations
