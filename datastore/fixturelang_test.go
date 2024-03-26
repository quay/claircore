package datastore_test

import (
	"bufio"
	"encoding"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"reflect"
	"strconv"
	"strings"
	"unicode"

	"github.com/hugelgupf/go-shlex"

	"github.com/quay/claircore"
)

func ParseFixture(name string, r io.Reader) (*Fixture, error) {
	f := Fixture{
		Manifest: new(claircore.Manifest),
		IndexReport: &claircore.IndexReport{
			Packages:      make(map[string]*claircore.Package),
			Distributions: make(map[string]*claircore.Distribution),
			Repositories:  make(map[string]*claircore.Repository),
			Environments:  make(map[string][]*claircore.Environment),
			//Files:         make(map[string]claircore.File),
		},
	}
	pc := parseCtx{
		CurRepositoryIDs: make([]string, 0, 2), // Do a little pre-allocation.
	}
	fv := reflect.ValueOf(&f)
	pcv := reflect.ValueOf(&pc)

	s := bufio.NewScanner(r)
	s.Split(bufio.ScanLines)
	lineNo := 0
	for s.Scan() {
		lineNo++
		line, _, _ := strings.Cut(s.Text(), "#")
		if len(line) == 0 {
			continue
		}

		var cmd string
		var args []string
		if i := strings.IndexFunc(line, unicode.IsSpace); i == -1 {
			cmd = line
		} else {
			cmd = line[:i]
			args = shlex.Split(line[i:])
		}

		prefix := ""
		if !strings.HasPrefix(cmd, "Add") ||
			!strings.HasPrefix(cmd, "Clear") ||
			!strings.HasPrefix(cmd, "Push") ||
			!strings.HasPrefix(cmd, "Pop") {
			prefix = "Add"
		}

		m := fv.MethodByName(prefix + cmd)
		if !m.IsValid() {
			return nil, fmt.Errorf("%s:%d: unrecognized command %q", name, lineNo, cmd)
		}
		av := reflect.ValueOf(args)
		res := m.Call([]reflect.Value{pcv, av})
		if errRet := res[0]; !errRet.IsNil() {
			return nil, fmt.Errorf("%s:%d: command %s: %w", name, lineNo, cmd, errRet.Interface().(error))
		}
	}
	if err := s.Err(); err != nil {
		return nil, err
	}

	return &f, nil
}

type Fixture struct {
	Manifest    *claircore.Manifest
	IndexReport *claircore.IndexReport
}

type parseCtx struct {
	CurLayer         *claircore.Layer
	CurDistribution  *claircore.Distribution
	CurSource        *claircore.Package
	CurPackageDB     string
	CurRepositoryIDs []string

	ManifestSet bool
}

func (f *Fixture) AddManifest(pc *parseCtx, args []string) (err error) {
	if len(args) != 1 {
		return errors.New("bad number of arguments: want exactly 1")
	}
	if pc.ManifestSet {
		return errors.New("bad command: Manifest already created")
	}
	f.Manifest.Hash, err = claircore.ParseDigest(args[0])
	if err != nil {
		return err
	}
	f.IndexReport.Hash = f.Manifest.Hash
	pc.ManifestSet = true
	return nil
}

func (f *Fixture) AddLayer(pc *parseCtx, args []string) error {
	if len(args) != 1 {
		return errors.New("bad number of arguments: want exactly 1")
	}
	if !pc.ManifestSet {
		return errors.New("bad command: no Manifest created")
	}
	d, err := claircore.ParseDigest(args[0])
	if err != nil {
		return err
	}

	l := claircore.Layer{
		URI:  "file:///dev/null",
		Hash: d,
	}
	f.Manifest.Layers = append(f.Manifest.Layers, &l)
	pc.CurLayer = &l
	return nil
}

func (f *Fixture) AddDistribution(pc *parseCtx, args []string) error {
	d := claircore.Distribution{}
	if err := handleStruct(pc, &d, args); err != nil {
		return err
	}
	pc.CurDistribution = &d
	return nil
}

func (f *Fixture) ClearDistribution(pc *parseCtx, args []string) error {
	if len(args) == 0 {
		return errors.New("bad number of arguments: want 0")
	}
	pc.CurDistribution = nil
	return nil
}

func (f *Fixture) PushRepository(pc *parseCtx, args []string) error {
	r := claircore.Repository{}
	if err := handleStruct(pc, &r, args); err != nil {
		return err
	}
	if r.ID == "" {
		r.ID = strconv.FormatInt(int64(len(f.IndexReport.Repositories)), 10)
	}
	f.IndexReport.Repositories[r.ID] = &r
	pc.CurRepositoryIDs = append(pc.CurRepositoryIDs, r.ID)
	return nil
}

func (f *Fixture) PopRepository(pc *parseCtx, args []string) error {
	if len(args) == 0 {
		return errors.New("bad number of arguments: want 0")
	}
	last := len(pc.CurRepositoryIDs) - 1
	pc.CurRepositoryIDs = pc.CurRepositoryIDs[:last]
	return nil
}

func (f *Fixture) AddPackage(pc *parseCtx, args []string) error {
	p := claircore.Package{}
	if err := handleStruct(pc, &p, args); err != nil {
		return err
	}
	if p.ID == "" {
		p.ID = strconv.FormatInt(int64(len(f.IndexReport.Packages)), 10)
	}
	p.Source = pc.CurSource
	f.IndexReport.Packages[p.ID] = &p
	env := claircore.Environment{
		PackageDB:     p.PackageDB,
		IntroducedIn:  pc.CurLayer.Hash,
		RepositoryIDs: pc.CurRepositoryIDs,
	}
	if pc.CurDistribution != nil {
		env.DistributionID = pc.CurDistribution.ID
	}
	f.IndexReport.Environments[p.ID] = []*claircore.Environment{&env}
	return nil
}

func handleStruct[T any](pc *parseCtx, tgt *T, args []string) (err error) {
	if len(args) == 0 {
		return errors.New("bad number of arguments: want 1 or more")
	}
	if !pc.ManifestSet {
		return errors.New("bad command: no Manifest created")
	}
	if pc.CurLayer == nil {
		return errors.New("bad command: no Layer created")
	}
	dv := reflect.ValueOf(tgt).Elem()
	for _, arg := range args {
		k, v, ok := strings.Cut(arg, "=")
		if !ok {
			return fmt.Errorf("malformed arg: %q", arg)
		}
		f := dv.FieldByName(k)
		if !f.IsValid() {
			return fmt.Errorf("unknown key: %q", k)
		}
		switch x := f.Addr().Interface(); x := x.(type) {
		case *int64:
			*x, err = strconv.ParseInt(v, 10, 0)
		case *int:
			var tmp int64
			tmp, err = strconv.ParseInt(v, 10, 0)
			if err == nil {
				*x = int(tmp)
			}
		case *string:
			*x = v
		case encoding.TextUnmarshaler:
			err = x.UnmarshalText([]byte(v))
		case json.Unmarshaler:
			err = x.UnmarshalJSON([]byte(v))
		}
		if err != nil {
			return fmt.Errorf("key %q: bad value %q: %w", k, v, err)
		}
	}
	return nil
}
