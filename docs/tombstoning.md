# The Vulnstore

An interface infront of Postgres implements how we store and retrieve vulnerabilities.
Updaterrs use the `csec.internal.vulnstore.Updater` interface to write Vulnerability data into the Vulnstore.
Matchers use the `csec.internal.vulnstore.Vulnerability` interface to read Vulnerability data from the Vulnstore.

## Tombstoning

In order to remove stale vulnerabilities from the VulnStore the Postgres implentation has a notion of "tombstoning".
Each time an updater sees changes, parses them, and calls the Vulnstore for update the Vulnstore will either create new record or update existing records with a new "tombstone".
Tombtones are implemented as simple UUIDs.
When the vulnstore is finished updating all new and existing records it them removes any records which do not have the new "tombstone". 
This effectively removes stale vulnerabilities from the Vulnstore with the implication that Updaters always parse the entire database and not perform incremental updates.

## Update Cursors 
A table called "update_cursor" is used to faciliate tombstoning and identifying if a discovered hash is equal to the existing one. 
See `csec.internal.vulnstore.Updater` for context.

