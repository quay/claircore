module github.com/quay/claircore

go 1.23.0

toolchain go1.24.1

require (
	github.com/Masterminds/semver v1.5.0
	github.com/doug-martin/goqu/v8 v8.6.0
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgconn v1.14.3
	github.com/jackc/pgtype v1.14.2
	github.com/jackc/pgx/v4 v4.18.3
	github.com/klauspost/compress v1.18.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/package-url/packageurl-go v0.1.3
	github.com/prometheus/client_golang v1.22.0
	github.com/quay/claircore/toolkit v1.2.4
	github.com/quay/claircore/updater/driver v1.0.0
	github.com/quay/goval-parser v0.8.8
	github.com/quay/zlog v1.1.8
	github.com/remind101/migrate v0.0.0-20170729031349-52c1edff7319
	github.com/rs/zerolog v1.30.0
	github.com/spdx/tools-golang v0.5.5
	github.com/ulikunitz/xz v0.5.11
	go.opentelemetry.io/otel v1.36.0
	go.opentelemetry.io/otel/trace v1.36.0
	go.uber.org/mock v0.5.2
	golang.org/x/crypto v0.39.0
	golang.org/x/net v0.41.0
	golang.org/x/sync v0.15.0
	golang.org/x/sys v0.33.0
	golang.org/x/text v0.26.0
	golang.org/x/time v0.12.0
	golang.org/x/tools v0.34.0
	modernc.org/sqlite v1.37.1
)

require (
	github.com/anchore/go-struct-converter v0.0.0-20221118182256-c68fdcfa2092 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.2 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20231201235250-de7065d80cb9 // indirect
	github.com/jackc/puddle v1.3.0 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/prometheus/client_model v0.6.1 // indirect
	github.com/prometheus/common v0.62.0 // indirect
	github.com/prometheus/procfs v0.15.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/metric v1.36.0 // indirect
	golang.org/x/exp v0.0.0-20250408133849-7e4ce0ab07d0 // indirect
	golang.org/x/mod v0.25.0 // indirect
	google.golang.org/protobuf v1.36.5 // indirect
	modernc.org/libc v1.65.7 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/quay/claircore/updater/driver => ./updater/driver
