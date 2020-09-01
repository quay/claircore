# What is ClairCore

ClairCore is the engine behind ClairV4's container security solution.
The ClairCore package exports our domain models, interfaces necessary to plug into our business logic, and a default set of implementations.
This default set of implementations define our support matrix and constists of the following distributions and languages:
-    Ubuntu
-    Debian
-    RHEL
-    Suse
-    Oracle
-    Alpine
-    AWS Linux
-    VMWare Photon
-    Python

ClairCore relies on postgres for its persistence and the library will handle migrations if configured so.

The below diagrams is a high level overview of ClairCore's architecture. 

![high_level_arch](./high_level_arch.png "a diagram of the high level claircore architecture")

When a claircore.Manifest is submitted to LibIndex the library will index its constintuent parts for later retrieval and create a report holding its findings.

When a claircore.IndexReport is provided to LibVuln the library will parse the report, discover vulnerabilities affecting this report, and generate a claircore.
