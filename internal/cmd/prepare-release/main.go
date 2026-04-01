// prepare-release automates the changelog bump and PR creation for a new release.
//
// It performs the following steps:
//  1. Checks for merged PRs that still need changelog entries
//  2. Fetches changelog notes from the remote
//  3. Generates the new changelog from git notes
//  4. Creates a branch, commits the changelog, and pushes
//  5. Creates a PR via the gh CLI
//
// Because the PR is created by a real user (via gh auth), CI workflows will
// trigger normally, avoiding the GITHUB_TOKEN limitation where automated PRs
// don't trigger workflows. gh must be installed and authenticated.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"strings"
)

type logHandler struct {
	dryRun bool
}

func (h *logHandler) Enabled(_ context.Context, _ slog.Level) bool { return true }

func (h *logHandler) Handle(_ context.Context, r slog.Record) error {
	var sb strings.Builder
	if h.dryRun {
		sb.WriteString("[dry-run] ")
	}
	sb.WriteString(r.Message)
	r.Attrs(func(a slog.Attr) bool {
		sb.WriteString(" ")
		sb.WriteString(a.Key)
		sb.WriteString("=")
		sb.WriteString(a.Value.String())
		return true
	})
	sb.WriteString("\n")
	fmt.Fprint(os.Stderr, sb.String())
	return nil
}

func (h *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler { return h }
func (h *logHandler) WithGroup(name string) slog.Handler       { return h }

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	var (
		branch string
		remote string
		repo   string
		dryRun bool
	)
	flag.StringVar(&branch, "branch", "", "branch to prepare the release against (default: current branch)")
	flag.StringVar(&remote, "remote", "", "git remote to use (default: upstream if exists, else origin)")
	flag.StringVar(&repo, "repo", "quay/claircore", "GitHub repository")
	flag.BoolVar(&dryRun, "dry-run", false, "show what would be done without making changes")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: prepare-release [flags] VERSION\n\n")
		fmt.Fprintf(os.Stderr, "Prepares a release by generating the changelog and creating a PR.\n\n")
		fmt.Fprintf(os.Stderr, "Flags:\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		return fmt.Errorf("missing VERSION argument")
	}

	if _, err := exec.LookPath("git"); err != nil {
		return fmt.Errorf("git not found in PATH: please install it")
	}
	if _, err := exec.LookPath("gh"); err != nil {
		return fmt.Errorf("gh not found in PATH: install from https://github.com/cli/cli")
	}

	version := flag.Arg(0)
	if !strings.HasPrefix(version, "v") {
		version = "v" + version
	}

	slog.SetDefault(slog.New(&logHandler{dryRun: dryRun}))

	// Default to current working branch if not specified.
	if branch == "" {
		out, err := exec.Command("git", "branch", "--show-current").Output()
		if err != nil {
			return fmt.Errorf("getting current branch: %v", err)
		}
		branch = strings.TrimSpace(string(out))
	}

	// Autodetect normals that use upstream+origin instead of origin+fork (weirdos).
	if remote == "" {
		out, err := exec.Command("git", "remote").Output()
		if err != nil {
			return fmt.Errorf("detecting remote: %v", err)
		}
		remote = "origin"
		for _, r := range strings.Split(strings.TrimSpace(string(out)), "\n") {
			if r == "upstream" {
				remote = "upstream"
				break
			}
		}
	}

	slog.Info("preparing release", "version", version, "branch", branch)

	if err := checkChangelogLabel(repo); err != nil {
		return err
	}

	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return fmt.Errorf("finding repo root: %v", err)
	}
	repoRoot := strings.TrimSpace(string(out))

	if err := fetchChangelogNotes(remote); err != nil {
		return fmt.Errorf("fetching changelog notes: %v", err)
	}

	prevTag, err := getPreviousTag()
	if err != nil {
		return fmt.Errorf("finding previous tag: %v", err)
	}
	slog.Info("found previous tag", "tag", prevTag)

	if dryRun {
		slog.Info("changelog preview")
		if err := renderChangelog(os.Stdout, prevTag, version, branch); err != nil {
			return fmt.Errorf("rendering changelog: %v", err)
		}
	} else {
		if err := updateChangelogFile(repoRoot, prevTag, version, branch); err != nil {
			return fmt.Errorf("updating changelog: %v", err)
		}
	}

	prBranch := "ready-" + version
	if err := createAndPushBranch(prBranch, version, remote, dryRun); err != nil {
		return fmt.Errorf("creating branch: %v", err)
	}

	if err := createPR(repo, branch, prBranch, version, dryRun); err != nil {
		return fmt.Errorf("creating PR: %v", err)
	}

	fmt.Printf(`
Now, to merge and release:
1. Wait for CI to pass and get a maintainer to approve the PR.
2. Locally merge, tag, and push:
	git checkout %[1]s
	git fetch %[2]s
	git merge --ff-only %[2]s/%[4]s
	git tag -s -m %[3]s %[3]s
	git push %[2]s %[1]s tag %[3]s
`, branch, remote, version, prBranch)
	return nil
}

// fetchChangelogNotes pulls the changelog git notes from the remote.
// This runs even in dry-run mode since it's read-only and needed for the changelog preview.
func fetchChangelogNotes(remote string) error {
	cmd := exec.Command("git", "fetch", "--tags", remote, "refs/notes/changelog:refs/notes/changelog")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type prInfo struct {
	Title string `json:"title"`
	URL   string `json:"url"`
}

// checkChangelogLabel queries GitHub for merged PRs that still have the
// "needs-changelog" label. These must be addressed before creating a release.
func checkChangelogLabel(repo string) error {
	prs, err := ghSearchPRs(repo, "needs-changelog")
	if err != nil {
		return err
	}
	if len(prs) > 0 {
		slog.Warn("PRs still need changelog entries")
		for _, pr := range prs {
			slog.Warn("pending PR", "url", pr.URL, "title", pr.Title)
		}
		return fmt.Errorf("pending changelog entries exist")
	}
	return nil
}

// ghSearchPRs searches for merged PRs with the given label.
func ghSearchPRs(repo, label string) ([]prInfo, error) {
	out, err := exec.Command("gh", "search", "prs",
		"--repo", repo,
		"--state", "closed",
		"--merged",
		"--label="+label,
		"--json=title,url",
	).Output()
	if err != nil {
		return nil, fmt.Errorf("searching PRs: %w", err)
	}
	var prs []prInfo
	if err := json.Unmarshal(out, &prs); err != nil {
		return nil, fmt.Errorf("parsing PR list: %w", err)
	}
	return prs, nil
}

// createAndPushBranch creates a new branch, commits the changelog changes and pushes to the remote.
func createAndPushBranch(prBranch, version, remote string, dryRun bool) error {
	cmds := [][]string{
		{"git", "checkout", "-b", prBranch},
		{"git", "add", "CHANGELOG.md"},
		{"git", "commit", "-s", "-m", fmt.Sprintf("chore: %s changelog bump", version)},
		{"git", "push", "-u", remote, prBranch},
	}

	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		if dryRun {
			slog.Info("would run", "cmd", cmd.String())
			continue
		}
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("running %s: %w", cmd.String(), err)
		}
	}

	return nil
}

// createPR creates a pull request for the changelog bump.
// Using gh (authenticated as the user) ensures that CI workflows trigger on the PR.
func createPR(repo, baseBranch, headBranch, version string, dryRun bool) error {
	title := fmt.Sprintf("%s Changelog Bump", version)
	body := "This is an automated changelog commit."
	cmd := exec.Command("gh", "pr", "create",
		"--repo", repo,
		"--base", baseBranch,
		"--head", headBranch,
		"--title", title,
		"--body", body,
	)
	if dryRun {
		// Can't use gh's --dry-run here since we don't wanna push the branch.
		slog.Info("would run", "cmd", cmd.String())
		return nil
	}
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}
	slog.Info("PR created", "url", strings.TrimSpace(out.String()))
	return nil
}
