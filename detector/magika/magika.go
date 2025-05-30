package magika

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"path"
)

func LoadModel(sys fs.FS, name string) (*Model, error) {
	ct, err := loadContentTypes(sys)
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

	m := Model{
		ct:     ct,
		config: config,
		model:  model,
	}
	return &m, nil
}

type Model struct {
	ct     map[string]ContentType
	config *Config
	model  []byte
}

func (m *Model) Scan(r io.ReaderAt, size int64) (ContentType, error) {
	if size == 0 {
		return m.ct[contentTypeLabelEmpty], nil
	}
	api, err := getapi()
	if err != nil {
		return ContentType{}, err
	}

	features, err := m.config.Features(r, size)
	if err != nil {
		return ContentType{}, err
	}
	session, err := api.CreateSession(m.model)
	if err != nil {
		return ContentType{}, err
	}
	scores, err := session.Run(features, len(m.config.TargetLabelsSpace))
	if err != nil {
		return ContentType{}, err
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
		return ContentType{}, fmt.Errorf("no content type found for %q", l)
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
		return m.ct[contentTypeLabelTxt], nil
	default:
		return m.ct[contentTypeLabelUnknown], nil
	}
}

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

func (cfg *Config) paddedInt32(b []byte, prefix, size int) []int32 {
	s := make([]int32, max(size, len(b)+prefix))
	pre, n, post := s[:prefix], s[prefix:][:len(b)], s[prefix+len(b):]

	for i := range pre {
		pre[i] = cfg.PaddingToken
	}
	for i, b := range b {
		n[i] = int32(b)
	}
	for i := range post {
		post[i] = cfg.PaddingToken
	}

	return s
}

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
	for i, b := range v {
		beg[i] = int32(b)
	}
	for i := range len(beg) - len(v) {
		beg[i+len(v)] = cfg.PaddingToken
	}

	_ = mid

	_ = end

	return out, nil
}

const (
	contentTypeLabelEmpty   = "empty"
	contentTypeLabelTxt     = "txt"
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

func loadContentTypes(sys fs.FS) (map[string]ContentType, error) {
	f, err := sys.Open(`content_types_kb.min.json`)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// TODO(hank) The json/v2 package would avoid the extra loop by reading and
	// modifying the objects directly as they streamed in.
	kb := make(map[string]ContentType)
	if err := json.NewDecoder(f).Decode(&kb); err != nil {
		return nil, err
	}
	for label, ct := range kb {
		ct.Label = label
		kb[label] = ct
	}
	return kb, nil
}
