// Mdbook-mermaid is a helper meant to slip-stream mermaid diagrams.
//
// The diagram will get built and slip-streamed where there's a codeblock of the
// "mermaid" type. For example:
//
//	```mermaid
//	graph LR
//		x --> y
//	```
package main

import (
	"context"
	"regexp"
	"strings"

	"github.com/quay/claircore/internal/mdbook"
)

var (
	marker = regexp.MustCompile("(?sUm)^```mermaid$.*^```$")
	repl   = strings.NewReplacer(
		"```mermaid", `<pre class="mermaid">`,
		"```", "</pre>",
		"<", "&lt;",
		">", "&gt;",
		`"`, "&quot;",
		"&", "&amp;",
	)
)

func main() {
	mdbook.Main("mermaid", newProc)
}

func newProc(ctx context.Context, cfg *mdbook.Context) (*mdbook.Proc, error) {
	proc := mdbook.Proc{
		Chapter: func(ctx context.Context, b *strings.Builder, c *mdbook.Chapter) error {
			c.Content = marker.ReplaceAllStringFunc(c.Content, func(m string) string {
				out := repl.Replace(m)
				return out
			})
			return nil
		},
	}
	return &proc, nil
}
