ALTER TABLE update_operation
    ADD COLUMN kind text;
CREATE INDEX on update_operation (kind);

UPDATE update_operation
SET kind = 'vulnerability';

CREATE TABLE enrichment
(
    id        BIGSERIAL PRIMARY KEY,
    hash_kind text,
    hash      bytea,
    updater   text,
    tags      text[],
    data      jsonb
);
CREATE UNIQUE INDEX ON enrichment (hash_kind, hash);
-- use inverted index for tags index
CREATE INDEX ON enrichment USING gin (tags);

CREATE TABLE uo_enrich
(
    uo          BIGINT REFERENCES update_operation (id),
    enrich      BIGINT REFERENCES enrichment (id),
    updater     text,
    fingerprint text,
    date        timestamptz,
    PRIMARY KEY (uo, enrich)
);
