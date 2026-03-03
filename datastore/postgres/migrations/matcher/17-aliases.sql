CREATE TABLE IF NOT EXISTS alias_namespace (
  id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  namespace TEXT UNIQUE NOT NULL
);

COMMENT ON TABLE alias_namespace IS 'Contains namespaces for aliases. Usually short IDs like "CVE" or "GHSA".';

CREATE TABLE IF NOT EXISTS alias (
  id INTEGER PRIMARY KEY GENERATED ALWAYS AS IDENTITY,
  namespace INTEGER NOT NULL REFERENCES alias_namespace (id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  UNIQUE (namespace, name)
);

COMMENT ON TABLE alias IS 'Table for all known aliases of vulnerabilities in the system. All vulnerabilities should have at least one alias.';

CREATE TABLE IF NOT EXISTS vulnerability_alias (
  vulnerability INTEGER REFERENCES vuln (id) ON DELETE CASCADE,
  alias INTEGER NOT NULL REFERENCES alias (id) ON DELETE CASCADE,
  PRIMARY KEY (vulnerability, alias)
);

COMMENT ON TABLE vulnerability_alias IS 'Pivot table linking vulnerabilities to aliases.';

CREATE TABLE IF NOT EXISTS vulnerability_self (
  vulnerability INTEGER PRIMARY KEY REFERENCES vuln (id) ON DELETE CASCADE,
  self INTEGER NOT NULL REFERENCES alias (id) ON DELETE CASCADE
);

COMMENT ON TABLE vulnerability_self IS 'Indicates the "self" alias for a vulnerability.';
