# Updaters and Defaults

The default updaters are tracked in `updater/defaults/defaults.go`.

## HTTP Resources

The following are the HTTP hosts and paths that Clair will attempt to
talk to in a default configuration. This list is non-exhaustive, as
some servers will issue redirects and some request URLs are constructed
dynamically.

- https://secdb.alpinelinux.org/
- http://repo.us-west-2.amazonaws.com/2018.03/updates/x86_64/mirror.list
- https://cdn.amazonlinux.com/2/core/latest/x86_64/mirror.list
- https://www.debian.org/security/oval/
- https://linux.oracle.com/security/oval/
- https://packages.vmware.com/photon/photon_oval_definitions/
- https://github.com/pyupio/safety-db/archive/
- https://catalog.redhat.com/api/containers/
- https://access.redhat.com/security/data/
- https://support.novell.com/security/oval/
- https://people.canonical.com/~ubuntu-security/oval/
