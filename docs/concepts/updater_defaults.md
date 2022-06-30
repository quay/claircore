# Updaters and Defaults

The default updaters are tracked in `updater/defaults/defaults.go`.

## HTTP Resources

The following are the HTTP hosts and paths that Clair will attempt to
talk to in a default configuration. This list is non-exhaustive, as
some servers will issue redirects and some request URLs are constructed
dynamically.

{{# injecturls updater }}
