# What is ClairCore

ClairCore is the engine behind ClairV4's container security solution.
The ClairCore package exports our domain models, interfaces necessary to plug into our business logic, and a default set of implementations.
This default set of implementations define our support matrix and consists of the following distributions and languages:
-    Ubuntu
-    Debian
-    RHEL
-    Suse
-    Oracle
-    Alpine
-    AWS Linux
-    VMWare Photon
-    Python

ClairCore relies on postgres for its persistence and the library will handle migrations if configured to do so.

The diagram below is a high level overview of ClairCore's architecture. 

![high_level_arch](./high_level_arch.png "a high level diagram of the claircore architecture")

When a claircore.Manifest is submitted to LibIndex, the library will index its constituent parts and create a report with its findings.

When a claircore.IndexReport is provided to LibVuln, the library will discover vulnerabilities affecting it and generate a claircore.VulnerabilityReport.
