package rpm

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"runtime/trace"
	"strings"

	"github.com/quay/zlog"

	"github.com/quay/claircore"
)

// This is the query format we're using to get data out of rpm.
//
// There's XML output, but it's all jacked up.
const queryFmt = `%{name}\n` +
	`%{evr}\n` +
	`%{payloaddigestalgo}:%{payloaddigest}\n` +
	`%{sigpgp:pgpsig}\n` +
	`%{sourcerpm}\n` +
	`%{RPMTAG_MODULARITYLABEL}\n` +
	`%{ARCH}\n` +
	`.\n`
const delim = "\n.\n"

func querySplit(data []byte, atEOF bool) (advance int, token []byte, err error) {
	i := bytes.Index(data, []byte(delim))
	switch {
	case len(data) == 0 && atEOF:
		return 0, nil, io.EOF
	case i == -1 && atEOF:
		return 0, nil, errors.New("invalid format")
	case i == -1 && !atEOF:
		return 0, nil, nil
	default:
	}
	tok := data[:i]
	return len(tok) + len(delim), tok, nil
}

func parsePackage(ctx context.Context, src map[string]*claircore.Package, buf *bytes.Buffer) (*claircore.Package, error) {
	defer trace.StartRegion(ctx, "parsePackage").End()
	p := claircore.Package{
		Kind: claircore.BINARY,
	}
	var err error
	var line string

	for i := 0; ; i++ {
		// Look at the "queryFmt" string for the line numbers.
		line, err = buf.ReadString('\n')
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "(none)") {
			continue
		}
		if line == "" && err == nil {
			zlog.Info(ctx).
				Str("package", p.Name).
				Int("lineno", i).
				Msg("unexpected empty line")
			continue
		}
		switch i {
		case 0:
			p.Name = line
		case 1:
			p.Version = line
		case 2:
			p.RepositoryHint = "hash:"
			switch line[0] {
			case '8': // sha256
				p.RepositoryHint += "sha256" + line[1:]
			}
		case 3:
			const delim = `Key ID `
			i := strings.Index(line, delim)
			if i == -1 { // ???
				break
			}
			p.RepositoryHint += "|key:" + line[i+len(delim):]
		case 4:
			line = strings.TrimSuffix(line, ".src.rpm")
			sp := strings.Split(line, "-")
			name := strings.Join(sp[:len(sp)-2], "-")
			if s, ok := src[name]; ok {
				p.Source = s
				break
			}
			p.Source = &claircore.Package{
				Name:    name,
				Version: sp[len(sp)-2] + "-" + sp[len(sp)-1],
				Kind:    claircore.SOURCE,
			}
			src[name] = p.Source
		case 5:
			moduleSplit := strings.Split(line, ":")
			if len(moduleSplit) < 2 {
				continue
			}
			moduleStream := fmt.Sprintf("%s:%s", moduleSplit[0], moduleSplit[1])
			p.Module = moduleStream
			if p.Source != nil {
				p.Source.Module = moduleStream
			}
		case 6:
			p.Arch = line
		}
		switch err {
		case nil:
		case io.EOF:
			return &p, nil
		default:
			return nil, err
		}
	}
}

// CheckMagic looks at bit of the provided Reader to see if it looks like a
// BerkeleyDB file.
//
// According to the libmagic database I looked at:
//
//	# Hash 1.85/1.86 databases store metadata in network byte order.
//	# Btree 1.85/1.86 databases store the metadata in host byte order.
//	# Hash and Btree 2.X and later databases store the metadata in host byte order.
//
// Since this process can't (and doesn't want to) know the endian-ness of the
// layer's eventual host, we just look both ways for everything.
func checkMagic(ctx context.Context, r io.Reader) bool {
	const (
		Hash  = 0x00061561
		BTree = 0x00053162
		Queue = 0x00042253
		Log   = 0x00040988
		// https://github.com/rpm-software-management/rpm/blob/be64821b908fdb1ff3c12530430d1cf046839e60/lib/backend/ndb/rpmpkg.c#L98
		// fmt.Printf("%08x", 'R'|'p'<<8|'m'<<16|'P'<<24)
		Ndb = 0x506d7052
	)
	// Most hosts are still x86, try LE first.
	be := []binary.ByteOrder{binary.LittleEndian, binary.BigEndian}
	b := make([]byte, 4)

	// Look at position 0 and 12 for a magic number.
	for _, discard := range []int64{0, 8} {
		if _, err := io.Copy(io.Discard, io.LimitReader(r, discard)); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unexpected error checking magic")
			return false
		}
		if _, err := io.ReadFull(r, b); err != nil {
			zlog.Warn(ctx).Err(err).Msg("unexpected error checking magic")
			return false
		}
		for _, o := range be {
			n := o.Uint32(b)
			if n == Hash || n == BTree || n == Queue || n == Log || n == Ndb {
				return true
			}
		}
	}

	return false
}
