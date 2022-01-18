# VersionFilter
`VersionFilter` is an additional interface a `Matcher` may implement.
If implemented, `Libvuln` will attempt to use the database and the normalized
version field of a package to filter vulnerabilities in the database. 
This is an opt-in optimization for when a package manager's version scheme can
be normalized into a `claircore.Version`. 

{{# godoc libvuln/driver.VersionFilter}}
