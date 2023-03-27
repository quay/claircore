//go:build tools
// +build tools

package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
)

func main() {
	ctx := context.Background()
	fs := make(map[int]map[string][]byte)
	for min := 3; ; min++ {
		f := make(map[string][]byte)
		for _, p := range paths {
			cmd := exec.CommandContext(ctx, `podman`, `run`, `--rm`, fmt.Sprintf("docker.io/library/alpine:3.%d", min), `cat`, p)
			b, err := cmd.Output()
			if err != nil {
				log.Println(min, p, err)
				continue
			}
			f[p] = b
		}
		if len(f) == 0 {
			break
		}
		fs[min] = f
	}
	for min, f := range fs {
		dir := `3.` + strconv.Itoa(min)
		for fn, b := range f {
			p := filepath.Join(dir, fn)
			if err := os.MkdirAll(filepath.Dir(p), 0755); err != nil {
				log.Println(p, err)
				continue
			}
			f, err := os.OpenFile(filepath.Join(dir, fn), os.O_CREATE|os.O_RDWR|os.O_TRUNC, 0644)
			if err != nil {
				log.Println(fn, err)
				continue
			}
			defer f.Close()
			if _, err := f.Write(b); err != nil {
				log.Println(fn, err)
			}
		}
	}
}

var paths = []string{"etc/os-release", "etc/issue"}
