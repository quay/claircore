/*
Package postgres implements the indexer store interface for a PostgreSQL
database.

SQL statements should be placed in files in sql/ and then turned into strings
via embed. The files can then be easily formatted by pg_format.

Queries should endeavor to do work database-side, as opposed to making queries
to construct further queries.
*/
package postgres
