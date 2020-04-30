package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path"
	"strings"
	"sync"
	"text/tabwriter"
	"text/template"
	"time"

	"github.com/quay/claircore"
)

const (
	// Note the tabs in this template. That's for the tabwriter.
	tabwriterTmpl = `
{{- define "ok" -}}
{{.Name}}	ok
{{end}}
{{- define "err" -}}
{{.Name}}	error	{{.Err}}
{{end}}
{{- define "found" -}}
{{with $r := .}}{{range $id, $v := .Report.PackageVulnerabilities}}{{range $d := $v -}}
{{$r.Name}}	found	{{with index $r.Report.Packages $id}}{{.Name}}	{{.Version}}{{end}}
	{{- with index $r.Report.Vulnerabilities $d}}	{{.Name}}
	{{- with .FixedInVersion}}	(fixed: {{.}}){{end}}{{end}}
{{end}}{{end}}{{end}}{{end}}
{{- /* The following is the actual bit of the template that runs per item. */ -}}
{{- range .}}{{if .Err}}{{template "err" .}}
{{- else if ne (len .Report.PackageVulnerabilities) 0}}{{template "found" .}}
{{- else}}{{template "ok" .}}
{{- end}}{{end}}`

	junitTmpl = `<?xml version="1.0" encoding="utf-8"?>
<testsuites>
{{- define "found" -}}
{{- with $r := . }}
	<testsuite name="{{ $r.Name }}"
	           time=""
	           tests="{{ len .Report.PackageVulnerabilities }}"
	           failures="{{ len .Report.PackageVulnerabilities }}">
		{{- range $id, $v := .Report.PackageVulnerabilities }}
		{{- range $d := $v }}
		<testcase classname=
			{{- with index $r.Report.Packages $id -}}
				"{{ .Name }} ({{ .Version }})"
			{{- end }}
		          name=
			{{- with index $r.Report.Vulnerabilities $d -}}
				"{{ .Name }} {{- with .FixedInVersion }} (fixed: {{ . }}){{ end }}"
			{{- end -}}
			>
			{{- with index $r.Report.Vulnerabilities $d }}
			<failure message="Failed" type="{{ .Severity }}"><![CDATA[
				{{ .Description }}
				{{- with .Links }} {{ . }}{{ end }}
				{{- with .Repo }} (from: {{ .Name }}){{ end }}
			]]></failure>
			{{- end }}
		</testcase>
		{{- end }}
		{{- end }}
	</testsuite>
{{- end -}}
{{- end -}}

{{- range . }}
{{- template "found" .}}
{{- end }}
</testsuites>
	`
)

var (
	zipSan = strings.NewReplacer(":", "-")
	fm     = template.FuncMap{
		"zipSan": func(s string) string { return zipSan.Replace(s) },
	}
)

type reportConfig struct {
	jqFilter          string
	timeout           time.Duration
	libindex, libvuln *url.URL
	dump              bool
	indexTmpl         *template.Template
	manifestTmpl      *template.Template
	reportTmpl        *template.Template
}

// Report is the subcommand for generating container reports.
func Report(cmd context.Context, cfg *commonConfig, args []string) error {
	cmdcfg := reportConfig{}
	fs := flag.NewFlagSet("cctool report", flag.ExitOnError)
	fs.StringVar(&cmdcfg.jqFilter, "jq", "", "run a jq filter on the manifest index before sending for matching")
	fs.DurationVar(&cmdcfg.timeout, "timeout", 5*time.Minute, "timeout for successful http responses")
	fs.BoolVar(&cmdcfg.dump, "dump", false, "dump indexreports to file described by dump-fmt")
	useJunitReport := fs.Bool("junit", false, "produce jUnit compatible report (instead of tabwriter)")
	libindexRoot := fs.String("libindex", "http://localhost:8080/", "address for a libindex api server")
	libvulnRoot := fs.String("libvuln", "http://localhost:8081/", "address for a libvuln api server")
	indexTmplString := fs.String("index-fmt", "{{.}}.index.json", "filenames to use when the dump flag is provided")
	manifestTmplString := fs.String("manifest-fmt", "{{.}}.manifest.json", "filenames to use when the dump flag is provided")
	reportTmplString := fs.String("report-fmt", "{{.}}.report.json", "filenames to use when the dump flag is provided")
	fs.Parse(args)

	images := fs.Args()
	if len(images) == 0 {
		s := bufio.NewScanner(os.Stdin)
		for s.Scan() {
			images = append(images, strings.TrimSpace(s.Text()))
		}
		if err := s.Err(); err != nil {
			return err
		}
	}
	libindex, err := url.Parse(*libindexRoot)
	if err != nil {
		return err
	}
	cmdcfg.libindex, err = libindex.Parse("index_report")
	if err != nil {
		return err
	}
	libvuln, err := url.Parse(*libvulnRoot)
	if err != nil {
		return err
	}
	cmdcfg.libvuln, err = libvuln.Parse("vulnerability_report")
	if err != nil {
		return err
	}
	cmdcfg.indexTmpl, err = template.New("dumpfile:index").Funcs(fm).Parse(*indexTmplString)
	if err != nil {
		return err
	}
	cmdcfg.manifestTmpl, err = template.New("dumpfile:manifest").Funcs(fm).Parse(*manifestTmplString)
	if err != nil {
		return err
	}
	cmdcfg.reportTmpl, err = template.New("dumpfile:report").Funcs(fm).Parse(*reportTmplString)
	if err != nil {
		return err
	}

	tmpl := tabwriterTmpl
	if *useJunitReport {
		tmpl = junitTmpl
	}

	outTmpl, err := template.New("output").Parse(tmpl)
	if err != nil {
		return err
	}

	type Result struct {
		Name   string
		Err    error
		Report *claircore.VulnerabilityReport
	}

	var errd bool
	var eo sync.Once
	var wg sync.WaitGroup
	ch := make(chan *Result)
	for _, img := range images {
		img := img
		name := path.Base(img)
		wg.Add(1)
		go func() {
			defer wg.Done()
			r, err := runManifest(cmd, img, cfg, &cmdcfg)
			if err != nil {
				eo.Do(func() { errd = true })
			}
			if cmdcfg.dump && err == nil {
				buf := bytes.Buffer{}
				func() {
					if err := cmdcfg.reportTmpl.Execute(&buf, name); err != nil {
						log.Print(err)
						return
					}
					f, err := os.Create(buf.String())
					if err != nil {
						log.Print(err)
						return
					}
					defer f.Close()
					if err := json.NewEncoder(f).Encode(&r); err != nil {
						log.Print(err)
					}
					log.Printf("wrote %q", buf.String())
				}()
			}
			ch <- &Result{
				Name:   name,
				Err:    err,
				Report: r,
			}
		}()
	}
	go func() {
		wg.Wait()
		close(ch)
	}()

	writer := (io.Writer)(os.Stdout)

	if !*useJunitReport {
		tw := tabwriter.NewWriter(os.Stdout, 0, 0, 1, ' ', 0)
		defer tw.Flush()
		writer = tw
	}

	if err := outTmpl.Execute(writer, ch); err != nil {
		return err
	}

	if errd {
		return errors.New("some requests failed")
	}
	return nil
}

func runManifest(ctx context.Context, img string, cfg *commonConfig, cmdcfg *reportConfig) (*claircore.VulnerabilityReport, error) {
	m, err := Inspect(ctx, img)
	if err != nil {
		return nil, err
	}
	buf := bytes.Buffer{}

	if err := json.NewEncoder(&buf).Encode(m); err != nil {
		return nil, err
	}
	if cmdcfg.dump {
		n := path.Base(img)
		// shadow this for our dumping
		buf := bytes.Buffer{}
		func() {
			if err := cmdcfg.manifestTmpl.Execute(&buf, n); err != nil {
				log.Print(err)
				return
			}
			f, err := os.Create(buf.String())
			if err != nil {
				log.Print(err)
				return
			}
			defer f.Close()
			if err := json.NewEncoder(f).Encode(m); err != nil {
				log.Print(err)
			}
			log.Printf("wrote %q", buf.String())
		}()
	}

	req, err := http.NewRequestWithContext(ctx, "POST", cmdcfg.libindex.String(), &buf)
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")

	var pollURL *url.URL
	res, err := http.DefaultClient.Do(req)
	switch {
	case err != nil:
		return nil, err
	case res.StatusCode == http.StatusCreated:
		pollURL, err = res.Location()
		if err != nil {
			return nil, err
		}
	case res.StatusCode == http.StatusOK: // Older versions issued redirects.
		pollURL = res.Request.URL
	default:
		return nil, fmt.Errorf("unexpected status: %q", res.Status)
	}

	var r claircore.IndexReport
	err = json.NewDecoder(res.Body).Decode(&r)
	res.Body.Close()
	if err != nil {
		return nil, err
	}

	tctx, done := context.WithTimeout(ctx, cmdcfg.timeout)
	defer done()
	interval := time.NewTicker(2 * time.Second)
	defer interval.Stop()
	for r.State != "IndexFinished" && r.State != "IndexErr" {
		select {
		case <-tctx.Done():
			return nil, tctx.Err()
		case <-interval.C:
		}

		req, err := http.NewRequestWithContext(tctx, "GET", pollURL.String(), nil)
		if err != nil {
			return nil, err
		}
		req.Header.Set("accept", "application/json")
		res, err := http.DefaultClient.Do(req)
		switch {
		case err != nil:
			return nil, err
		case res.StatusCode == http.StatusOK:
		default:
			return nil, fmt.Errorf("unexpected status: %q", res.Status)
		}
		err = json.NewDecoder(res.Body).Decode(&r)
		res.Body.Close()
		if err != nil {
			return nil, err
		}
	}
	if r.State == "IndexError" {
		return nil, errors.New(r.Err)
	}
	if cmdcfg.dump {
		n := path.Base(img)
		// shadow this for our dumping
		buf := bytes.Buffer{}
		func() {
			if err := cmdcfg.indexTmpl.Execute(&buf, n); err != nil {
				log.Print(err)
				return
			}
			f, err := os.Create(buf.String())
			if err != nil {
				log.Print(err)
				return
			}
			defer f.Close()
			if err := json.NewEncoder(f).Encode(&r); err != nil {
				log.Print(err)
			}
			log.Printf("wrote %q", buf.String())
		}()
	}

	if err := json.NewEncoder(&buf).Encode(&r); err != nil {
		return nil, err
	}
	var send io.Reader = &buf
	if f := cmdcfg.jqFilter; f != "" {
		cmd := exec.CommandContext(ctx, "jq", f)
		cmd.Stderr = os.Stderr
		cmd.Stdin = &buf
		buf := bytes.Buffer{}
		cmd.Stdout = &buf
		send = &buf
	}
	req, err = http.NewRequestWithContext(ctx, "POST", cmdcfg.libvuln.String(), send)
	if err != nil {
		return nil, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("accept", "application/json")
	res, err = http.DefaultClient.Do(req)
	switch {
	case err != nil:
		return nil, err
	case res.StatusCode == http.StatusOK:
	default:
		return nil, fmt.Errorf("unexpected status: %q", res.Status)
	}

	var vs claircore.VulnerabilityReport
	err = json.NewDecoder(res.Body).Decode(&vs)
	res.Body.Close()
	if err != nil {
		return nil, err
	}
	return &vs, nil

}
