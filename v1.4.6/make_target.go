//go:build ignore
// +build ignore

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lmsgprefix)
	log.SetPrefix("make_target: ")
	defer func() {
		if errored {
			os.Exit(1)
		}
	}()

	// Handle when called with "supports $renderer".
	if len(os.Args) == 3 {
		switch os.Args[1] {
		case "supports":
			switch os.Args[2] {
			case "html":
			default:
				os.Exit(1)
			}
		default:
			os.Exit(1)
		}
		os.Exit(0)
	}

	// Actual preprocessing mode.
	log.Println("running preprocessor")

	in := make([]json.RawMessage, 2)
	dec := json.NewDecoder(os.Stdin)
	if err := dec.Decode(&in); err != nil {
		panic(err)
	}
	var cfg Config
	if err := json.Unmarshal(in[0], &cfg); err != nil {
		panic(err)
	}
	var book Book
	if err := json.Unmarshal(in[1], &book); err != nil {
		panic(err)
	}

	var b strings.Builder
	for _, s := range book.Sections {
		if err := s.Process(&b, &cfg); err != nil {
			panic(err)
		}
	}
	if err := json.NewEncoder(os.Stdout).Encode(&book); err != nil {
		panic(err)
	}
}

var (
	open     sync.Once
	makefile []byte
	errored  bool
)

// in: {"root":"/var/home/hank/work/clair/clair","config":{"book":{"authors":["Clair Authors"],"description":"Documentation for Clair.","language":"en","multilingual":false,"src":"Documentation","title":"Clair Documentation"},"output":{"html":{"git-repository-url":"https://github.com/quay/clair","preferred-dark-theme":"coal"}},"preprocessor":{"history":{"command":"go run Documentation/history.go"}}},"renderer":"html","mdbook_version":"0.4.13"}
type Config struct {
	Root     string `json:"root"`
	Renderer string `json:"renderer"`
	Version  string `json:"mdbook_version"`
	Config   struct {
		Book BookConfig `json:"book"`
	} `json:"config"`
}

type BookConfig struct {
	Source string `json:"src"`
}

type Book struct {
	Sections []Section `json:"sections"`
	X        *struct{} `json:"__non_exhaustive"`
}

type Section struct {
	Chapter   *Chapter    `json:",omitempty"`
	Separator interface{} `json:",omitempty"`
	PartTitle string      `json:",omitempty"`
}

func (s *Section) Process(b *strings.Builder, cfg *Config) error {
	if s.Chapter != nil {
		return s.Chapter.Process(b, cfg)
	}
	return nil
}

type Chapter struct {
	Name        string    `json:"name"`
	Content     string    `json:"content"`
	Number      []int     `json:"number"`
	SubItems    []Section `json:"sub_items"`
	Path        *string   `json:"path"`
	SourcePath  *string   `json:"source_path"`
	ParentNames []string  `json:"parent_names"`
}

func (c *Chapter) Process(b *strings.Builder, cfg *Config) error {
	if c.Path != nil {
		c.Content = marker.ReplaceAllStringFunc(c.Content, func(sub string) string {
			ms := marker.FindStringSubmatch(sub)
			if ct := len(ms); ct != 2 {
				err := fmt.Errorf("unexpected number of arguments: %d", ct)
				log.Panic(err)
			}
			target := strings.TrimSpace(ms[1])
			re, err := regexp.Compile("\n" + target + `:`)
			if err != nil {
				log.Panic(err)
			}

			open.Do(func() {
				cmd := exec.Command(`git`, `rev-parse`, `--show-toplevel`)
				out, err := cmd.Output()
				if err != nil {
					log.Panic(err)
				}
				n := filepath.Join(string(bytes.TrimSpace(out)), `Makefile`)
				log.Printf("opening %q", n)
				makefile, err = os.ReadFile(n)
				if err != nil {
					log.Panic(err)
				}
				log.Print("OK")
			})

			if !re.Match(makefile) {
				log.Printf("unable to find target %q", target)
				errored = true
			}
			return target
		})
	}
	for _, s := range c.SubItems {
		if err := s.Process(b, cfg); err != nil {
			return err
		}
	}
	return nil
}

var marker = regexp.MustCompile(`\{\{#\s*make_target\s(.+)\}\}`)
