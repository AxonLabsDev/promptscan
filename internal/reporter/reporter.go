// Package reporter formats scan results for console and JSON output.
package reporter

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/fatih/color"
)

// Severity levels for scan results.
type Severity int

const (
	Clean   Severity = iota
	Warn             // score 20-50
	Suspect          // score 50-80
	Blocked          // score > 80
)

func (s Severity) String() string {
	switch s {
	case Clean:
		return "CLEAN"
	case Warn:
		return "WARN"
	case Suspect:
		return "SUSPECT"
	case Blocked:
		return "BLOCKED"
	default:
		return "UNKNOWN"
	}
}

// FileResult is the outcome of scanning a single file.
type FileResult struct {
	Path     string   `json:"path"`
	Score    float64  `json:"score"`
	Severity Severity `json:"severity"`
	Findings []string `json:"findings,omitempty"`
	Line     int      `json:"line,omitempty"` // first suspicious line
}

// ScanReport aggregates all file results.
type ScanReport struct {
	Version    string        `json:"version"`
	ScannedAt  time.Time     `json:"scanned_at"`
	TotalFiles int           `json:"total_files"`
	Duration   time.Duration `json:"duration"`
	Threshold  float64       `json:"threshold"`
	Results    []FileResult  `json:"results"`
}

// Classify determines severity based on score and threshold.
func Classify(score float64, blockThreshold float64) Severity {
	switch {
	case score >= blockThreshold:
		return Blocked
	case score >= 50:
		return Suspect
	case score >= 20:
		return Warn
	default:
		return Clean
	}
}

// PrintConsole writes a colored console report.
func PrintConsole(w io.Writer, report ScanReport, quiet bool) {
	bold := color.New(color.Bold)
	red := color.New(color.FgRed, color.Bold)
	yellow := color.New(color.FgYellow, color.Bold)
	cyan := color.New(color.FgCyan)
	green := color.New(color.FgGreen, color.Bold)

	bold.Fprintf(w, "PromptScan %s", report.Version)
	fmt.Fprintf(w, " -- scanned %d files in %s\n\n", report.TotalFiles, report.Duration.Round(time.Millisecond))

	// Sort results by score descending.
	sort.Slice(report.Results, func(i, j int) bool {
		return report.Results[i].Score > report.Results[j].Score
	})

	// Group by severity.
	var blocked, suspect, warn, clean []FileResult
	for _, r := range report.Results {
		switch r.Severity {
		case Blocked:
			blocked = append(blocked, r)
		case Suspect:
			suspect = append(suspect, r)
		case Warn:
			warn = append(warn, r)
		case Clean:
			clean = append(clean, r)
		}
	}

	if len(blocked) > 0 {
		red.Fprintf(w, "BLOCKED (score >= %.0f):\n", report.Threshold)
		for _, r := range blocked {
			fmt.Fprintf(w, "  [%3.0f] %s", r.Score, r.Path)
			if r.Line > 0 {
				fmt.Fprintf(w, ":%d", r.Line)
			}
			if len(r.Findings) > 0 {
				fmt.Fprintf(w, "        %s", strings.Join(r.Findings, " + "))
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}

	if len(suspect) > 0 {
		yellow.Fprintln(w, "SUSPECT (score 50-80):")
		for _, r := range suspect {
			fmt.Fprintf(w, "  [%3.0f] %s", r.Score, r.Path)
			if r.Line > 0 {
				fmt.Fprintf(w, ":%d", r.Line)
			}
			if len(r.Findings) > 0 {
				fmt.Fprintf(w, "        %s", strings.Join(r.Findings, " + "))
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}

	if len(warn) > 0 && !quiet {
		cyan.Fprintln(w, "WARN (score 20-50):")
		for _, r := range warn {
			fmt.Fprintf(w, "  [%3.0f] %s", r.Score, r.Path)
			if r.Line > 0 {
				fmt.Fprintf(w, ":%d", r.Line)
			}
			if len(r.Findings) > 0 {
				fmt.Fprintf(w, "        %s", strings.Join(r.Findings, " + "))
			}
			fmt.Fprintln(w)
		}
		fmt.Fprintln(w)
	}

	if !quiet {
		green.Fprintf(w, "CLEAN: %d files\n\n", len(clean))
	}

	// Summary line.
	bold.Fprintf(w, "Summary: %d blocked, %d suspect, %d warn, %d clean\n",
		len(blocked), len(suspect), len(warn), len(clean))
}

// PrintJSON writes a JSON report.
func PrintJSON(w io.Writer, report ScanReport) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(report)
}
