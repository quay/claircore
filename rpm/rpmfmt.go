// +build ignore

// This is a tiny tool to play with rpm format queries.
package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"os"
	"os/exec"
	"strings"
)

func main() {
	ctx := context.Background()

	cmd := exec.CommandContext(ctx, `rpm`, `--querytags`)
	out, err := cmd.Output()
	if err != nil {
		log.Fatal(err)
	}
	buf := bytes.NewBuffer(out)
	var tags []string
	for tag, err := buf.ReadString('\n'); err == nil; tag, err = buf.ReadString('\n') {
		tags = append(tags, strings.TrimSpace(tag))
	}

	b := &strings.Builder{}
	for _, t := range tags {
		fmt.Fprintf(b, "%s: %%{%s}\\n", strings.Title(t), t)
	}
	fmt.Fprint(b, ".\\n")

	cmd = exec.CommandContext(ctx, `rpm`, `--query`, `--queryformat`, b.String(), `bash`)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		log.Fatal(err)
	}
}
