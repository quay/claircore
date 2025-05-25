# Examples

### Vulnerability Report
The `vulnreport` example shows all the necessary steps for generating a
vulnerability report, including connecting to a PostgreSQL database,
configuring the indexer and matcher, constructing a container image in
claircore terms, producing an index report, and producting a vulnerability
report.

This example requires a PostgreSQL database server. It's configured with the
same credentials as the `claircore-db` from the `docker-compose.yaml`, i.e.,
to get started, run `docker-compose up -d`.
