// Package magika implements bindings for the [magika] file type detector.
//
// The model runs on the [ONNX Runtime]; the ONNX Runtime libraries are required
// and will be dynamically loaded as needed.
//
// [magika]: https://github.com/google/magika/
// [ONNX Runtime]: https://onnxruntime.ai/
package magika

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
)

// LoadModel loads the named model from the provided [fs.FS].
//
// The FS is assumed to be structured like the upstream repository's "assets"
// folder.
func LoadModel(sys fs.FS, name string) (*Model, error) {
	ct, err := LoadContentTypes(sys)
	if err != nil {
		return nil, err
	}

	config, err := LoadConfig(sys, name)
	if err != nil {
		return nil, err
	}

	p := path.Join(`models`, name, `model.onnx`)
	model, err := fs.ReadFile(sys, p)
	if err != nil {
		return nil, err
	}

	api, err := getAPI()
	if err != nil {
		return nil, err
	}
	session, err := api.CreateSession(model)
	if err != nil {
		return nil, err
	}

	m := Model{
		ct:      ct,
		config:  config,
		model:   model,
		session: session,
	}
	return &m, nil
}

// Model is a loaded magika model.
//
// This type should provide the same concurrency guarantees as the underlying
// [OrtSession] type.
//
// [OrtSession]: https://onnxruntime.ai/docs/api/c/group___global.html#ga5220ca3b3f0a31a01a3f15057c35cac6
type Model struct {
	ct     map[string]*ContentType
	config *Config
	// I don't think the C-side session object copies the model data, so keep
	// the slice around.
	model   []byte
	session *session
}

// Scan extracts features from the provided [io.ReaderAt] and runs the model,
// reporting the highest confidence result.
func (m *Model) Scan(r io.ReaderAt, size int64) (*ContentType, error) {
	if size == 0 {
		return m.ct[contentTypeLabelEmpty], nil
	}

	features, err := m.config.Features(r, size)
	if err != nil {
		return nil, err
	}
	scores, err := m.session.Run(features, len(m.config.TargetLabelsSpace))
	if err != nil {
		return nil, err
	}
	best := 0
	for i, v := range scores {
		if v > scores[best] {
			best = i
		}
	}
	score := scores[best]
	l := m.config.TargetLabelsSpace[best]
	ct, ok := m.ct[l]
	if !ok {
		return nil, fmt.Errorf("no content type found for %q", l)
	}
	th := m.config.MediumConfidenceThreshold
	if t, ok := m.config.Thresholds[l]; ok {
		th = t
	}

	// Return the inferred content type if the threshold is met, otherwise
	// falls back to a relevant default.
	switch {
	case score >= th:
		return ct, nil
	case ct.IsText:
		return m.ct[contentTypeLabelText], nil
	default:
		return m.ct[contentTypeLabelUnknown], nil
	}
}

// LoadConfig loads the configuration of the named model from the provided
// [fs.FS].
//
// The FS is assumed to be structured like the upstream repository's "assets"
// folder.
func LoadConfig(sys fs.FS, name string) (*Config, error) {
	p := path.Join(`models`, name, `config.min.json`)
	f, err := sys.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var cfg Config
	if err := json.NewDecoder(f).Decode(&cfg); err != nil {
		return nil, err
	}
	return &cfg, nil
}

// Config is the model configuration.
type Config struct {
	BegSize                   int                `json:"beg_size"`
	MidSize                   int                `json:"mid_size"`
	EndSize                   int                `json:"end_size"`
	UseInputsAtOffsets        bool               `json:"use_inputs_at_offsets"`
	MediumConfidenceThreshold float32            `json:"medium_confidence_threshold"`
	MinFileSizeForDl          int64              `json:"min_file_size_for_dl"`
	PaddingToken              int32              `json:"padding_token"`
	BlockSize                 int                `json:"block_size"`
	TargetLabelsSpace         []string           `json:"target_labels_space"`
	Thresholds                map[string]float32 `json:"thresholds"`
}

// PaddedInt32 places "b" into "out" starting at index "prefix", setting any
// bytes before and after to the [Config.PaddingToken].
//
// This function assumes the "out" slice is zeroed.
func (cfg *Config) paddedInt32(out []int32, b []byte, prefix int) {
	pre, n, post := out[:prefix], out[prefix:][:len(b)], out[prefix+len(b):]

	if cfg.PaddingToken != 0 {
		for i := range pre {
			pre[i] = cfg.PaddingToken
		}
	}
	for i, b := range b {
		n[i] = int32(b)
	}
	if cfg.PaddingToken != 0 {
		for i := range post {
			post[i] = cfg.PaddingToken
		}
	}
}

// Features extracts the configured features from the provided [io.ReaderAt].
func (cfg *Config) Features(r io.ReaderAt, size int64) ([]int32, error) {
	const spaces = " \f\n\r\t\v"
	out := make([]int32, cfg.BegSize+cfg.MidSize+cfg.EndSize)
	beg := out[:cfg.BegSize]
	mid := out[cfg.BegSize:][:cfg.MidSize]
	end := out[cfg.BegSize+cfg.MidSize:]
	var v []byte
	b := make([]byte, cfg.BlockSize)

	n, err := r.ReadAt(b, 0)
	switch {
	case err == nil:
	case err == io.EOF:
	default:
		return nil, err
	}
	v = b[:n]
	v = bytes.TrimLeft(v, spaces)
	v = v[:min(len(v), cfg.BegSize)]
	cfg.paddedInt32(beg, v, 0)

	n, err = r.ReadAt(b[:cfg.MidSize], (size-int64(cfg.MidSize))/2)
	switch {
	case err == nil:
	case err == io.EOF:
	default:
		return nil, err
	}
	v = b[:n]
	v = v[:min(len(v), cfg.EndSize)]
	cfg.paddedInt32(mid, v, (cfg.MidSize-len(v))/2)

	n, err = r.ReadAt(b, max(size-int64(cfg.BlockSize), 0))
	switch {
	case err == nil:
	case err == io.EOF:
	default:
		return nil, err
	}
	v = b[:n]
	v = bytes.TrimRight(v, spaces)
	v = v[:min(len(v), cfg.EndSize)]
	cfg.paddedInt32(end, v, cfg.EndSize-len(v))

	return out, nil
}

const (
	contentTypeLabelEmpty   = "empty"
	contentTypeLabelText    = "txt"
	contentTypeLabelUnknown = "unknown"
)

// ContentType holds the definition of a content type.
type ContentType struct {
	Label       string   // As keyed in the content types KB.
	MimeType    string   `json:"mime_type"`
	Group       string   `json:"group"`
	Description string   `json:"description"`
	Extensions  []string `json:"extensions"`
	IsText      bool     `json:"is_text"`
}

// String implements [fmt.Stringer].
func (ct *ContentType) String() string {
	return ct.MimeType
}

// LoadContentTypes loads known [ContentType]s from the provided [fs.FS].
//
// The FS is assumed to be structured like the upstream repository's "assets"
// folder.
func LoadContentTypes(sys fs.FS) (map[string]*ContentType, error) {
	f, err := sys.Open(`content_types_kb.min.json`)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	kb := make(map[string]*ContentType)

	dec := json.NewDecoder(f)
	if tok, err := dec.Token(); tok != json.Delim('{') || err != nil {
		return nil, fmt.Errorf("unexpected content_types formatting: %v / %w", tok, err)
	}
	for dec.More() {
		tok, err := dec.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("unexpected content_types formatting: %v / %w", tok, err)
		}
		key, ok := tok.(string)
		if !ok {
			return nil, fmt.Errorf("unexpected content_types formatting: got: %T, want: string", tok)
		}

		var ct ContentType
		if err := dec.Decode(&ct); err != nil {
			return nil, fmt.Errorf("unexpected content_types formatting: %w", err)
		}
		ct.Label = key
		kb[key] = &ct

	}

	return kb, nil
}
