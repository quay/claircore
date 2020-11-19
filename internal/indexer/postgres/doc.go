/*
Package postgres implements the indexer store interface for a PostgreSQL
database.

SQL statements should be arranged in this package such that they're
constants in the closest scope possible to where they're used. They
should be run through sqlfmt and then checked for correctness, as sqlfmt
doesn't fully understand the PostgreSQL dialect. Queries should endeavor
to do work database-side, as opposed to making queries to construct
further queries.
*/
package postgres
