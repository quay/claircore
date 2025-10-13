module github.com/quay/claircore

go 1.24.0

toolchain go1.24.3

require (
	github.com/Masterminds/semver v1.5.0
	github.com/doug-martin/goqu/v8 v8.6.0
	github.com/google/go-cmp v0.7.0
	github.com/google/uuid v1.6.0
	github.com/jackc/pgconn v1.14.3
	github.com/jackc/pgx/v5 v5.7.6
	github.com/klauspost/compress v1.18.0
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/package-url/packageurl-go v0.1.3
	github.com/prometheus/client_golang v1.23.2
	github.com/quay/claircore/toolkit v1.2.4
	github.com/quay/claircore/updater/driver v1.0.0
	github.com/quay/goval-parser v0.8.8
	github.com/quay/zlog v1.1.9
	github.com/remind101/migrate v0.0.0-20170729031349-52c1edff7319
	github.com/rs/zerolog v1.32.0
	github.com/spdx/tools-golang v0.5.5
	github.com/ulikunitz/xz v0.5.15
	go.opentelemetry.io/otel v1.38.0
	go.opentelemetry.io/otel/trace v1.38.0
	go.uber.org/mock v0.6.0
	golang.org/x/crypto v0.42.0
	golang.org/x/net v0.44.0
	golang.org/x/sync v0.17.0
	golang.org/x/sys v0.36.0
	golang.org/x/text v0.29.0
	golang.org/x/time v0.13.0
	golang.org/x/tools v0.37.0
	modernc.org/sqlite v1.39.1
)

require (
	github.com/anchore/go-struct-converter v0.0.0-20221118182256-c68fdcfa2092 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-logr/stdr v1.2.2 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.3 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	github.com/jackc/puddle/v2 v2.2.2 // indirect
	github.com/kylelemons/godebug v1.1.0 // indirect
	github.com/lib/pq v1.10.2 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	go.opentelemetry.io/auto/sdk v1.1.0 // indirect
	go.opentelemetry.io/otel/metric v1.38.0 // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/mod v0.28.0 // indirect
	google.golang.org/protobuf v1.36.8 // indirect
	modernc.org/libc v1.66.10 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/quay/claircore/updater/driver => ./updater/driver
