package reporter

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestClassify(t *testing.T) {
	tests := []struct {
		score     float64
		threshold float64
		expected  Severity
	}{
		{0, 80, Clean},
		{19.9, 80, Clean},
		{20, 80, Warn},
		{49.9, 80, Warn},
		{50, 80, Suspect},
		{79.9, 80, Suspect},
		{80, 80, Blocked},
		{100, 80, Blocked},
		{60, 60, Blocked}, // custom threshold
	}

	for _, tc := range tests {
		got := Classify(tc.score, tc.threshold)
		if got != tc.expected {
			t.Errorf("Classify(%.1f, %.0f) = %v, want %v", tc.score, tc.threshold, got, tc.expected)
		}
	}
}

func TestSeverityString(t *testing.T) {
	if Clean.String() != "CLEAN" {
		t.Errorf("Clean.String() = %q", Clean.String())
	}
	if Blocked.String() != "BLOCKED" {
		t.Errorf("Blocked.String() = %q", Blocked.String())
	}
}

func TestPrintConsole(t *testing.T) {
	report := ScanReport{
		Version:    "v0.1.0",
		ScannedAt:  time.Now(),
		TotalFiles: 3,
		Duration:   100 * time.Millisecond,
		Threshold:  80,
		Results: []FileResult{
			{Path: "clean.md", Score: 0, Severity: Clean},
			{Path: "warn.md", Score: 25, Severity: Warn, Findings: []string{"encoding_detected(base64)"}},
			{Path: "blocked.md", Score: 92, Severity: Blocked, Findings: []string{"hash_match(5)", "role_reassignment"}, Line: 42},
		},
	}

	var buf bytes.Buffer
	PrintConsole(&buf, report, false)
	output := buf.String()

	if !strings.Contains(output, "PromptScan v0.1.0") {
		t.Error("output should contain version")
	}
	if !strings.Contains(output, "3 files") {
		t.Error("output should contain file count")
	}
	if !strings.Contains(output, "blocked.md") {
		t.Error("output should contain blocked file")
	}
	if !strings.Contains(output, "Summary:") {
		t.Error("output should contain summary")
	}
}

func TestPrintConsoleQuiet(t *testing.T) {
	report := ScanReport{
		Version:    "v0.1.0",
		ScannedAt:  time.Now(),
		TotalFiles: 2,
		Duration:   50 * time.Millisecond,
		Threshold:  80,
		Results: []FileResult{
			{Path: "clean.md", Score: 0, Severity: Clean},
			{Path: "clean2.md", Score: 5, Severity: Clean},
		},
	}

	var buf bytes.Buffer
	PrintConsole(&buf, report, true)
	output := buf.String()

	// In quiet mode, CLEAN count should not appear.
	if strings.Contains(output, "CLEAN:") {
		t.Error("quiet mode should not show CLEAN count")
	}
}

func TestPrintJSON(t *testing.T) {
	report := ScanReport{
		Version:    "v0.1.0",
		ScannedAt:  time.Now(),
		TotalFiles: 1,
		Duration:   10 * time.Millisecond,
		Threshold:  80,
		Results: []FileResult{
			{Path: "test.md", Score: 45, Severity: Warn, Findings: []string{"imperative_ratio(0.60)"}},
		},
	}

	var buf bytes.Buffer
	err := PrintJSON(&buf, report)
	if err != nil {
		t.Fatalf("PrintJSON failed: %v", err)
	}

	// Verify it's valid JSON.
	var parsed map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("output is not valid JSON: %v", err)
	}

	if parsed["version"] != "v0.1.0" {
		t.Errorf("JSON version: got %v", parsed["version"])
	}
}
