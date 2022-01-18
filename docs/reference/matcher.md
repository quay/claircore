# Matcher
A Matcher performs the heavy lifting of matching manifest contents to relevant
vulnerabilities. These implementations provide the smarts for understanding if a
particular artifact in a layer is vulnerable to a particular advisory in the
database.

{{# godoc libvuln/driver.Matcher}}

The `Filter` method is used to inform `Libvuln` the provided artifact is
interesting.
The `Query` method tells `Libvuln` how to query the security advisory database.
The `Vulnerable` method reports whether the provided package is vulnerable to
the provided vulnerability. Typically, this would perform a version check
between the artifact and the vulnerability in question.
