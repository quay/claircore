module github.com/quay/claircore

go 1.17

require (
	github.com/Masterminds/semver v1.5.0
	github.com/aquasecurity/go-pep440-version v0.0.0-20210121094942-22b2f8951d46
	github.com/cespare/xxhash/v2 v2.1.2 // indirect
	github.com/doug-martin/goqu/v8 v8.6.0
	github.com/golang/mock v1.6.0
	github.com/google/go-cmp v0.5.9
	github.com/google/uuid v1.3.0
	github.com/jackc/pgconn v1.13.0
	github.com/jackc/pgtype v1.8.1
	github.com/jackc/pgx/v4 v4.13.0
	github.com/klauspost/compress v1.15.11
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/matttproud/golang_protobuf_extensions v1.0.2-0.20181231171920-c182affec369 // indirect
	github.com/prometheus/client_golang v1.9.0
	github.com/prometheus/client_model v0.2.0
	github.com/prometheus/procfs v0.6.0 // indirect
	github.com/quay/alas v1.0.1
	github.com/quay/claircore/updater/driver v1.0.0
	github.com/quay/goval-parser v0.8.8
	github.com/quay/zlog v1.1.4
	github.com/remind101/migrate v0.0.0-20170729031349-52c1edff7319
	github.com/rs/zerolog v1.28.0
	github.com/ulikunitz/xz v0.5.10
	golang.org/x/crypto v0.0.0-20220722155217-630584e8d5aa
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/text v0.3.7
	golang.org/x/time v0.0.0-20210220033141-f8bda1e9f3ba
	golang.org/x/tools v0.1.9
	google.golang.org/protobuf v1.27.1 // indirect
	modernc.org/sqlite v1.19.1
)

require (
	github.com/aquasecurity/go-version v0.0.0-20210121072130-637058cfe492 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/golang/protobuf v1.5.0 // indirect
	github.com/jackc/chunkreader/v2 v2.0.1 // indirect
	github.com/jackc/pgio v1.0.0 // indirect
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgproto3/v2 v2.3.1 // indirect
	github.com/jackc/pgservicefile v0.0.0-20200714003250-2b9c44734f2b // indirect
	github.com/jackc/puddle v1.1.3 // indirect
	github.com/kballard/go-shellquote v0.0.0-20180428030007-95032a82bc51 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.16 // indirect
	github.com/prometheus/common v0.15.0 // indirect
	github.com/quay/claircore/toolkit v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20200410134404-eec4a21b6bb0 // indirect
	go.opentelemetry.io/otel v1.11.0 // indirect
	golang.org/x/mod v0.5.1 // indirect
	golang.org/x/sys v0.0.0-20221013171732-95e765b1cc43 // indirect
	golang.org/x/xerrors v0.0.0-20200804184101-5ec99f83aff1 // indirect
	lukechampine.com/uint128 v1.1.1 // indirect
	modernc.org/cc/v3 v3.38.1 // indirect
	modernc.org/ccgo/v3 v3.16.9 // indirect
	modernc.org/libc v1.19.0 // indirect
	modernc.org/mathutil v1.5.0 // indirect
	modernc.org/memory v1.4.0 // indirect
	modernc.org/opt v0.1.3 // indirect
	modernc.org/strutil v1.1.3 // indirect
	modernc.org/token v1.0.1 // indirect
)

replace github.com/quay/claircore/toolkit => ./toolkit

replace github.com/quay/claircore/updater/driver => ./updater/driver
