// Package mermaid is an mdbook preprocessor meant to slip-stream mermaid
// diagrams.
//
// The diagram will get built and slip-streamed where there's a codeblock of the
// "mermaid" type. For example:
//
//	```mermaid
//	graph LR
//		x --> y
//	```
package mermaid

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

// Register registers the preprocessor.
func Register(_ context.Context, _ *mdbook.Context, p *mdbook.Proc) error {
	p.Chapter(chapter)
	return nil
}

func chapter(_ context.Context, _ *strings.Builder, c *mdbook.Chapter) error {
	c.Content = marker.ReplaceAllStringFunc(c.Content, func(m string) string {
		return repl.Replace(m)
	})
	return nil
}
