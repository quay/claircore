module github.com/quay/claircore

go 1.16

require (
	github.com/Masterminds/semver v1.5.0
	github.com/aquasecurity/go-pep440-version v0.0.0-20210121094942-22b2f8951d46
	github.com/crgimenes/goconfig v1.2.1
	github.com/doug-martin/goqu/v8 v8.6.0
	github.com/golang/mock v1.6.0
	github.com/google/go-cmp v0.5.7
	github.com/google/go-containerregistry v0.0.0-20191206185556-eb7c14b719c6
	github.com/google/uuid v1.3.0
	github.com/jackc/pgconn v1.10.0
	github.com/jackc/pgtype v1.8.1
	github.com/jackc/pgx/v4 v4.13.0
	github.com/klauspost/compress v1.13.6
	github.com/knqyf263/go-apk-version v0.0.0-20200609155635-041fdbb8563f
	github.com/knqyf263/go-deb-version v0.0.0-20190517075300-09fca494f03d
	github.com/knqyf263/go-rpm-version v0.0.0-20170716094938-74609b86c936
	github.com/prometheus/client_golang v1.11.0
	github.com/prometheus/client_model v0.2.0
	github.com/quay/alas v1.0.1
	github.com/quay/claircore/toolkit v1.0.0
	github.com/quay/claircore/updater/driver v1.0.0
	github.com/quay/goval-parser v0.8.6
	github.com/quay/zlog v1.1.0
	github.com/remind101/migrate v0.0.0-20170729031349-52c1edff7319
	github.com/rs/zerolog v1.26.1
	github.com/ulikunitz/xz v0.5.8
	golang.org/x/sync v0.0.0-20210220032951-036812b2e83c
	golang.org/x/text v0.3.7
	golang.org/x/time v0.0.0-20210723032227-1f47c861a9ac
	golang.org/x/tools v0.1.9
	gopkg.in/yaml.v3 v3.0.0-20210107192922-496545a6307b
)

require (
	github.com/docker/docker v1.4.2-0.20191101170500-ac7306503d23 // indirect
	golang.org/x/exp/jsonrpc2 v0.0.0-20220325121720-054d8573a5d8
	golang.org/x/sys v0.0.0-20220209214540-3681064d5158 // indirect
)

replace github.com/quay/claircore/toolkit => ./toolkit

replace github.com/quay/claircore/updater/driver => ./updater/driver
