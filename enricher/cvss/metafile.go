package cvss

import (
	"bytes"
	"io"
	"strconv"
	"strings"
	"time"
)

// Metafile is the information contained in a ".meta" file.
//
// This is used to detect changes and only fetch new data when necessary.
type metafile struct {
	LastModified time.Time
	Size         int64
	ZipSize      int64
	GZSize       int64
	SHA256       string
}

func (m *metafile) Parse(buf *bytes.Buffer) (err error) {
	var l string
	for l, err = buf.ReadString('\n'); l != "" || err == nil; l, err = buf.ReadString('\n') {
		sl := strings.SplitN(strings.TrimSpace(l), ":", 2)
		switch sl[0] {
		case "lastModifiedDate":
			m.LastModified, err = time.Parse(time.RFC3339, sl[1])
		case "size":
			m.Size, err = strconv.ParseInt(sl[1], 10, 64)
		case "zipSize":
			m.ZipSize, err = strconv.ParseInt(sl[1], 10, 64)
		case "gzSize":
			m.GZSize, err = strconv.ParseInt(sl[1], 10, 64)
		case "sha256":
			m.SHA256 = sl[1]
		default:
			// ignore
		}
		if err != nil {
			return err
		}
	}
	if err != nil && err != io.EOF {
		return err
	}
	return nil
}
