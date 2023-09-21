# Severity Mapping

Claircore will normalize a security databases's severity string to a set of defined values.
Clients may use the `NormalizedSeverity` field on a `claircore.Vulnerability` to react to vulnerability severities without needing to know each security database's severity strings.
All strings used in the mapping tables are identical to the strings found within the relevant security database.

## Claircore Severity Strings
The following are severity strings Claircore will normalize others to.
Clients can guarantee one of these strings will be associated with a claircore.Vulnerability.

- Unknown
- Negligible
- Low
- Medium
- High
- Critical

<!-- Filter to fix the tables: column -o \| -s \| -t -->

## Alpine Mapping

Alpine SecDB database does not provide severity information.
All vulnerability severities will be Unknown.

| Alpine Severity | Claircore Severity |
| -               | -                  |
| *               | Unknown            |

## AWS Mapping

AWS UpdateInfo database provides severity information.

| AWS Severity | Claircore Severity |
| -            | -                  |
| low          | Low                |
| medium       | Medium             |
| important    | High               |
| critical     | Critical           |

## Debian Mapping

Debian Oval database does not provide severity information.
All vulnerability severities will be Unknown.

| Debian Severity | Claircore Severity |
| -               | -                  |
| *               | Unknown            |

## Oracle Mapping

Oracle Oval database provides severity information.

| Oracle Severity | Claircore Severity |
| -               | -                  |
| N/A             | Unknown            |
| LOW             | Low                |
| MODERATE        | Medium             |
| IMPORTANT       | High               |
| CRITICAL        | Critical           |

## RHEL Mapping

RHEL Oval database provides severity information.

| RHEL Severity | Claircore Severity |
| -             | -                  |
| None          | Unknown            |
| Low           | Low                |
| Moderate      | Medium             |
| Important     | High               |
| Critical      | Critical           |

## SUSE Mapping

SUSE Oval database provides severity information.

| SUSE Severity | Claircore Severity |
| -             | -                  |
| None          | Unknown            |
| Low           | Low                |
| Moderate      | Medium             |
| Important     | High               |
| Critical      | Critical           |

## Ubuntu Mapping

Ubuntu Oval database provides severity information.

| Ubuntu Severity | Claircore Severity |
| -               | -                  |
| Untriaged       | Unknown            |
| Negligible      | Negligible         |
| Low             | Low                |
| Medium          | Medium             |
| High            | High               |
| Critical        | Critical           |

## Photon Mapping

Photon Oval database provides severity information.

| Photon Severity | Claircore Severity |
| -               | -                  |
| Low             | Low                |
| Moderate        | Medium             |
| Important       | High               |
| Critical        | Critical           |

## OSV Mapping

OSV provides severity information via CVSS vectors, when applicable.
These are normalized according to the [NVD qualitative rating scale](https://nvd.nist.gov/vuln-metrics/cvss).
If both v3 and v2 vectors are present, v3 is preferred.

### CVSSv3

| Base Score | Claircore Severity  |
| -          | -                   |
| 0.0        | Negligible          |
| 0.1-3.9    | Low                 |
| 4.0-6.9    | Medium              |
| 7.0-8.9    | High                |
| 9.0-10.0   | Critical            |

### CVSSv2

| Base Score  | Claircore Severity   |
| -           | -                    |
| 0.0-3.9     | Low                  |
| 4.0-6.9     | Medium               |
| 7.0-10.0    | High                 |
