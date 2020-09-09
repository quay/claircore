# Severity Mapping

ClairCore will normalize a security databases's severity string to a set of defined values.
Clients may use the `NormalizedSeverity` field on a `claircore.Vulnerability` to react to vulnerability severities without needing to know each security database's severity strings.
All strings used in the mapping tables are identical to the strings found within the relevant security database.

## ClairCore Severity Strings
The following are severity strings ClairCore will normalize others to.
Clients can guarantee one of these strings will be associated with a claircore.Vulnerability.
```
Unknown
Negligible
Low
Medium
High
Critical
Defcon1
```

## Alpine Mapping

Alpine SecDB database does not provide severity information.
All vulnerability severities will be Unknown.

| Alpine Severity | Clair Severity |
| - | - |
| * | Unknown |

## AWS Mapping

AWS UpdateInfo database provides severity information.

| AWS Severity | Clair Severity |
| - | - |
| low | Low |
| medium | Medium |
| important | High |
| critical | Critical |

## Debian Mapping

Debian Oval database does not provide severity information.
All vulnerability severities will be Unknown.

| Debian Severity | Clair Severity |
| - | - |
| * | Unknown |

## Oracle Mapping

Oracle Oval database provides severity information.

| Oracle Severity | Clair Severity |
| - | - |
| N/A | Unknown |
| LOW | Low |
| MODERATE | Medium |
| IMPORTANT | High |
| CRITICAL | Critical

## RHEL Mapping

RHEL Oval database provides severity information.

| RHEL Severity | Clair Severity |
| - | - |
| None | Unknown |
| Low | Low |
| Moderate | Medium |
| Important | High |
| Critical | Critical |

## SUSE Mapping

SUSE Oval database provides severity information.

| SUSE Severity | Clair Severity |
| - | - |
| None | Unknown |
| Low | Low |
| Moderate | Medium |
| Important | High |
| Critical | Critical |

## Ubuntu Mapping

Ubuntu Oval database provides severity information.

| Ubuntu Severity | Clair Severity |
| - | - |
| Untriaged | Unknown |
| Negligible | Negligible |
| Low | Low |
| Medium | Medium |
| High | High |
| Critical | Critical |

## Pyupio Mapping

The pyup.io database does not have a concept of "severity".
All vulnerability severities will be Unknown.

| Pyupio Severity | Clair Severity |
| - | - |
| * | Unknown |
