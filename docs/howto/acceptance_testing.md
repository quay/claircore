# Acceptance Testing Framework

This package provides a testing framework for validating vulnerability analyzers
against known fixtures. It enables teams to verify that their analyzer correctly
identifies vulnerabilities in container images using VEX documents.

## Table of Contents

- [Acceptance Testing Framework](#acceptance-testing-framework)
  - [Table of Contents](#table-of-contents)
  - [Overview](#overview)
  - [Prerequisites](#prerequisites)
  - [Quick Start](#quick-start)
  - [Creating Fixtures](#creating-fixtures)
    - [VEX Document Format](#vex-document-format)
    - [Expected Results CSV](#expected-results-csv)
    - [Uploading Fixtures](#uploading-fixtures)
      - [Create Options](#create-options)
  - [Running Tests](#running-tests)
    - [Running Integration Tests](#running-integration-tests)
    - [Using Local OCI Layout](#using-local-oci-layout)
  - [Testing with Claircore](#testing-with-claircore)
  - [Implementing a Custom Auditor](#implementing-a-custom-auditor)
  - [Media Types](#media-types)

## Overview

The acceptance testing framework works by:

1. Loading test **fixtures** from an OCI registry (images with VEX documents and
   expected results attached as OCI referrers)
2. Running an **analyzer** (wrapped by the `Auditor` interface) against each fixture
3. Comparing the analyzer's output against the expected results

This approach allows reproducible, automated testing of vulnerability detection
without requiring access to the analyzer's internal implementation.

## Prerequisites

- **Go 1.25+** installed
- **Container registry access** with push permissions (for creating fixtures)

Note: The integration tests use embedded PostgreSQL binaries that are downloaded
automatically - no database installation required.

## Quick Start

If you just want to run the existing tests against the default fixtures repository:

```bash
go test -tags=integration -v ./test/acceptance/...
```

The tests will automatically pull fixtures from `quay.io/projectquay/clair-fixtures`.

## Creating Fixtures

A fixture consists of three parts:

1. A container image (the thing being analyzed)
2. One or more VEX documents describing vulnerabilities
3. An expected results CSV defining what the analyzer should find

### VEX Document Format

VEX documents must be valid [CSAF 2.0](https://docs.oasis-open.org/csaf/csaf/v2.0/csaf-v2.0.html)
with `category: csaf_vex`. Here's a minimal example:

```json
{
  "document": {
    "category": "csaf_vex",
    "csaf_version": "2.0",
    "publisher": {
      "category": "vendor",
      "name": "Your Organization",
      "namespace": "https://example.com"
    },
    "title": "CVE-2024-1234: Example vulnerability",
    "tracking": {
      "current_release_date": "2024-01-01T00:00:00Z",
      "id": "CVE-2024-1234",
      "initial_release_date": "2024-01-01T00:00:00Z",
      "revision_history": [
        {"date": "2024-01-01T00:00:00Z", "number": "1", "summary": "Initial"}
      ],
      "status": "final",
      "version": "1"
    }
  },
  "product_tree": {
    "branches": [
      {
        "category": "product_version",
        "name": "mypackage-1.2.3",
        "product": {
          "name": "My Package 1.2.3",
          "product_id": "mypackage-1.2.3",
          "product_identification_helper": {
            "purl": "pkg:pypi/mypackage@1.2.3"
          }
        }
      }
    ]
  },
  "vulnerabilities": [
    {
      "cve": "CVE-2024-1234",
      "product_status": {
        "known_affected": ["mypackage-1.2.3"]
      }
    }
  ]
}
```

Key fields:

| Field | Description |
|-------|-------------|
| `document.tracking.id` | The CVE/tracking ID (must match CSV) |
| `product_tree.branches[].product.product_id` | Product identifier (must match CSV) |
| `product_tree.branches[].product.product_identification_helper.purl` | Package URL for matching |
| `vulnerabilities[].product_status.known_affected` | List of affected product IDs |
| `vulnerabilities[].product_status.known_not_affected` | List of not-affected product IDs |

### Expected Results CSV

The expected results file is a CSV with three columns (no header row):

```csv
tracking_id,product_id,status
```

Example:

```csv
CVE-2024-1234,mypackage-1.2.3,affected
CVE-2024-5678,otherpackage-2.0.0,not_affected
CVE-2024-9999,fixedpackage-3.0.0,absent
```

| Status | Meaning | Test Behavior |
|--------|---------|---------------|
| `affected` | Product is vulnerable | MUST appear in analyzer results as affected |
| `not_affected` | Product is known to not be affected | MUST appear in analyzer results as not-affected |
| `absent` | Product should not appear (fixed/filtered) | MUST NOT appear in analyzer results |

Lines starting with `#` are treated as comments.

### Uploading Fixtures

Use the `test/acceptance/cmd/fixture` tool to create fixtures:

```bash
# Create a fixture
go run ./test/acceptance/cmd/fixture create \
    -image registry.io/namespace/image@sha256:abc123... \
    -tag my-fixture-name \
    -vex path/to/vex.json \
    -manifest path/to/expected.csv \
    -repo your.registry.io/namespace/your-repo

# You can attach multiple VEX documents
go run ./test/acceptance/cmd/fixture create \
    -image registry.io/namespace/image@sha256:abc123... \
    -tag multi-vex-fixture \
    -vex vex1.json \
    -vex vex2.json \
    -vex vex3.json \
    -manifest expected.csv \
    -repo your.registry.io/your-repo

# Verify the fixture was created
go run ./test/acceptance/cmd/fixture list -image your.registry.io/your-repo:my-fixture-name
```

#### Create Options

| Flag | Default | Description |
|------|---------|-------------|
| `-image` | (required) | Source image reference with digest |
| `-tag` | (required) | Tag name for the fixture |
| `-vex` | (required) | Path to VEX document (repeatable) |
| `-manifest` | (required) | Path to expected results CSV |
| `-repo` | `quay.io/projectquay/clair-fixtures` | Target repository |
| `-platform` | `linux/amd64` | Platform to copy (use `all` for multi-arch) |

## Running Tests

### Running Integration Tests

The integration tests automatically download and run embedded PostgreSQL
binaries - no database setup required:

```bash
go test -tags=integration -v ./test/acceptance/...
```

### Using Local OCI Layout

For testing without a registry, fixtures can be loaded from local OCI Layout
directories:

```go
acceptance.Run(ctx, t, auditor, []string{
    "ocidir:///path/to/local/fixture",
})
```

## Testing with Claircore

Most teams will use the built-in claircore auditor to test their images.
See [`integration_test.go`](../../test/acceptance/integration_test.go) for a
complete example showing how to set up and run acceptance tests with the
`ClaircoreAuditor`.

To run:

```bash
go test -tags=integration -v ./test/acceptance/...
```

The test will:
1. Pull each fixture from the registry
2. Index the image with claircore
3. Load the VEX documents attached to the image
4. Match vulnerabilities against the indexed packages
5. Compare results to the expected results CSV
6. Report any mismatches or missing vulnerabilities

## Implementing a Custom Auditor

If you're building your own vulnerability analyzer (not using claircore), implement
the `Auditor` interface:

See the [`Auditor`](https://pkg.go.dev/github.com/quay/claircore/test/acceptance#Auditor) interface and [`Result`](https://pkg.go.dev/github.com/quay/claircore/test/acceptance#Result) type documentation.

See [`example_test.go`](../../test/acceptance/example_test.go) for a complete, type-checked example implementation.

## Media Types

| Type | Media Type | Description |
|------|------------|-------------|
| VEX | `application/csaf+json` | CSAF/VEX vulnerability document |
| Expected Results | `application/vnd.com.redhat.container.acceptancetest.v1+csv` | Test expectations CSV |

Compressed variants (`...+zstd`) are also supported.
