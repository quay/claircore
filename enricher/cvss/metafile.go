package cvss

import (
	"bytes"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"
)

// Metafile is the information contained in a ".meta" file.
//
// This is used to detect changes and only fetch new data when necessary.
type metafile struct {
	SHA256       string
	LastModified time.Time
	Size         int64
	ZipSize      int64
	GZSize       int64
}

func (m *metafile) Parse(buf *bytes.Buffer) (err error) {
	var l string
	for l, err = buf.ReadString('\n'); err == nil; l, err = buf.ReadString('\n') {
		k, v, ok := strings.Cut(strings.TrimSpace(l), ":")
		if !ok {
			continue
		}
		switch k {
		case "lastModifiedDate":
			m.LastModified, err = time.Parse(time.RFC3339, v)
		case "size":
			m.Size, err = strconv.ParseInt(v, 10, 64)
		case "zipSize":
			m.ZipSize, err = strconv.ParseInt(v, 10, 64)
		case "gzSize":
			m.GZSize, err = strconv.ParseInt(v, 10, 64)
		case "sha256":
			m.SHA256 = v
		default:
			// ignore
		}
		if err != nil {
			return err
		}
	}
	if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
