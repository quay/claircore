package main

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

const (
	notesRef   = "refs/notes/changelog"
	compareURL = "https://github.com/quay/claircore/compare"
)

// getPreviousTag finds the most recent version tag merged into the current branch.
func getPreviousTag() (string, error) {
	out, err := exec.Command("git", "tag", "--sort=-taggerdate", "--merged").Output()
	if err != nil {
		return "", fmt.Errorf("listing tags: %w", err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.HasPrefix(line, "v") {
			return line, nil
		}
	}
	return "", fmt.Errorf("no version tags found")
}

// renderChangelog generates the changelog content for a new release.
// It reads git notes from commits between previous tag and the branch.
func renderChangelog(w io.Writer, prevTag, nextTag, branch string) error {
	// Write header
	fmt.Fprintf(w, "<a name=\"%s\"></a>\n", nextTag)
	fmt.Fprintf(w, "## [%s] - %s\n", nextTag, time.Now().Format("2006-01-02"))
	fmt.Fprintf(w, "[%s]: %s/%s...%s\n\n", nextTag, compareURL, prevTag, nextTag)

	// Get commits since prevTag on the target branch
	out, err := exec.Command("git", "rev-list", prevTag+".."+branch).Output()
	if err != nil {
		return fmt.Errorf("listing commits: %w", err)
	}

	hasNotes := false
	for _, commit := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if commit == "" {
			continue
		}
		note, err := getCommitNote(commit)
		if err != nil || note == "" {
			continue
		}
		hasNotes = true
		formatted := formatNote(note)
		fmt.Fprint(w, formatted)
	}

	if !hasNotes {
		fmt.Fprintln(w, "Nothing interesting happened this release.")
		fmt.Fprintln(w)
	}

	return nil
}

// getCommitNote retrieves the changelog note for a commit.
func getCommitNote(commit string) (string, error) {
	cmd := exec.Command("git", "notes", "--ref="+notesRef, "show", commit)
	out, err := cmd.Output()
	if err != nil {
		// No soup for you
		return "", err
	}
	return string(out), nil
}

// formatNote formats a changelog note into markdown.
func formatNote(note string) string {
	var sb strings.Builder
	lines := strings.Split(strings.TrimSpace(note), "\n")

	hasEmptyLine := false
	for _, line := range lines {
		if line == "" {
			hasEmptyLine = true
			break
		}
	}

	if hasEmptyLine {
		// Do the details thing
		first := true
		inDetails := false
		for _, line := range lines {
			line = linkifyJira(line)
			if first {
				sb.WriteString("- ")
				sb.WriteString(line)
				sb.WriteString("\n")
				first = false
			} else if line == "" && !inDetails {
				sb.WriteString("  <details>\n")
				inDetails = true
			} else {
				sb.WriteString("  ")
				sb.WriteString(line)
				sb.WriteString("\n")
			}
		}
		if inDetails {
			sb.WriteString("  </details>\n")
		}
	} else {
		// Just print it
		for _, line := range lines {
			line = linkifyJira(line)
			sb.WriteString(line)
			sb.WriteString("\n")
		}
	}
	sb.WriteString("\n")

	return sb.String()
}

var jiraPattern = regexp.MustCompile(`(PROJQUAY|CLAIRDEV)-[0-9]+`)

const jiraURL = "https://redhat.atlassian.net/browse"

// linkifyJira replaces PROJQUAY-XXX with markdown links.
func linkifyJira(s string) string {
	return jiraPattern.ReplaceAllStringFunc(s, func(match string) string {
		return fmt.Sprintf("[%s](%s/%s)", match, jiraURL, match)
	})
}

// updateChangelogFile renders the new changelog section, reads the existing changelog
// into memory and then writes the new changelog section then the existing changelog.
func updateChangelogFile(repoRoot, prevTag, nextTag, branch string) error {
	changelogPath := filepath.Join(repoRoot, "CHANGELOG.md")

	// Render new content
	var newChangelog strings.Builder
	if err := renderChangelog(&newChangelog, prevTag, nextTag, branch); err != nil {
		return fmt.Errorf("rendering changelog: %w", err)
	}

	// Read existing changelog
	existing, err := os.ReadFile(changelogPath)
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("reading existing changelog: %w", err)
	}

	// Write new changelog (prepend new content)
	f, err := os.Create(changelogPath)
	if err != nil {
		return fmt.Errorf("creating changelog: %w", err)
	}
	defer f.Close()

	bw := bufio.NewWriter(f)
	bw.WriteString(newChangelog.String())
	bw.Write(existing)
	if err := bw.Flush(); err != nil {
		return fmt.Errorf("writing changelog: %w", err)
	}

	return nil
}
