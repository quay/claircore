package osv

import (
	"time"
)

// The database dumps are hosted in an S3-compatible API, so this speaks just
// enough of the protocol to do discovery.

type listBucketResult struct {
	Name                  string
	ContinuationToken     string
	NextContinuationToken string
	Contents              []contents
	KeyCount              int
	IsTruncated           bool
}

type contents struct {
	Key            string
	Etag           string `xml:"ETag"`
	Generation     int64
	MetaGeneration int64
	LastModified   time.Time
	Size           int64
}
