package postgres

import (
	"crypto/md5"
	"errors"
	"io"
	"sort"
	"strconv"
	"strings"

	"github.com/quay/claircore/toolkit/types"
	"github.com/quay/claircore/updater/driver/v1"
)

func errLabel(e error) string {
	return strconv.FormatBool(!errors.Is(e, nil))
}

func hashEnrichment(r *driver.EnrichmentRecord) (k string, d []byte) {
	h := md5.New()
	sort.Strings(r.Tags)
	for _, t := range r.Tags {
		io.WriteString(h, t)
		h.Write([]byte("\x00"))
	}
	h.Write(r.Enrichment)
	return "md5", h.Sum(nil)
}

func rangefmt(r types.Range) (kind string, lower, upper string) {
	lower, upper = "{}", "{}"
	if r.Lower.Kind != r.Upper.Kind {
		return kind, lower, upper
	}
	kind = r.Lower.Kind // Just tested the both kinds are the same.
	if kind == "" {
		return kind, lower, upper
	}

	v := &r.Lower
	var buf strings.Builder
	b := make([]byte, 0, 16) // 16 byte wide scratch buffer

	buf.WriteByte('{')
	for i := 0; i < 10; i++ {
		if i != 0 {
			buf.WriteByte(',')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	buf.WriteByte('}')
	lower = buf.String()
	buf.Reset()
	v = &r.Upper
	buf.WriteByte('{')
	for i := 0; i < 10; i++ {
		if i != 0 {
			buf.WriteByte(',')
		}
		buf.Write(strconv.AppendInt(b, int64(v.V[i]), 10))
	}
	buf.WriteByte('}')
	upper = buf.String()

	return kind, lower, upper
}
