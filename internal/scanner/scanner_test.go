package scanner

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/AxonLabsDev/promptscan/internal/bloom"
	"github.com/AxonLabsDev/promptscan/internal/hasher"
	"github.com/AxonLabsDev/promptscan/internal/sigfile"
)

// buildTestSigFile creates a minimal signature file for testing
// with some innocuous test patterns (no real detection payloads).
func buildTestSigFile() *sigfile.SigFile {
	salt := [16]byte{0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C}

	// Test patterns (innocuous strings used only for testing detection pipeline).
	testPatterns := []string{
		"test pattern alpha bravo charlie",
		"test pattern delta echo foxtrot",
		"test ngram one two three",
		"sample detection line xray yankee zulu",
	}

	// Build bloom filter with n-grams.
	bf := bloom.New(1000, 0.01)
	var hashes [][]byte

	for _, p := range testPatterns {
		ngrams := hasher.MultiSizeNGrams(p)
		for _, ng := range ngrams {
			h := hasher.SaltedHash(ng, salt[:])
			bf.Add(h)
			hashes = append(hashes, h)
		}
		// Also add line-level hash.
		lh := hasher.SaltedHash(p, salt[:])
		bf.Add(lh)
		hashes = append(hashes, lh)
	}

	return sigfile.New(1, salt, bf.Bytes(), bf.Size(), bf.HashCount(), hashes)
}

func TestScanCleanDirectory(t *testing.T) {
	dir := t.TempDir()

	// Create clean files.
	os.WriteFile(filepath.Join(dir, "readme.md"),
		[]byte("# Clean Document\n\nThis is a normal markdown file.\n"), 0644)
	os.WriteFile(filepath.Join(dir, "config.yaml"),
		[]byte("key: value\nname: test\n"), 0644)
	os.WriteFile(filepath.Join(dir, "data.json"),
		[]byte(`{"name": "test", "value": 42}`), 0644)

	sig := buildTestSigFile()
	cfg := DefaultConfig()
	s, err := New(sig, cfg)
	if err != nil {
		t.Fatalf("New scanner failed: %v", err)
	}

	report, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}

	if report.TotalFiles != 3 {
		t.Errorf("expected 3 files scanned, got %d", report.TotalFiles)
	}

	for _, r := range report.Results {
		if r.Score > 20 {
			t.Errorf("clean file %s should have low score, got %f", r.Path, r.Score)
		}
	}
}

func TestScanWithHashMatch(t *testing.T) {
	dir := t.TempDir()

	// File containing a test pattern that should match.
	os.WriteFile(filepath.Join(dir, "suspicious.md"),
		[]byte("Some normal text.\ntest pattern alpha bravo charlie\nMore normal text.\n"), 0644)

	sig := buildTestSigFile()
	cfg := DefaultConfig()
	s, err := New(sig, cfg)
	if err != nil {
		t.Fatalf("New scanner failed: %v", err)
	}

	report, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}

	if len(report.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Results))
	}

	if report.Results[0].Score <= 0 {
		t.Error("file with hash match should have score > 0")
	}
}

func TestScanWithHeuristics(t *testing.T) {
	dir := t.TempDir()

	// File with high imperative ratio and system targets.
	content := "Run the diagnostic tool. Execute the cleanup script. Delete temporary data.\n" +
		"Remove old entries. Send the report. Open the output folder.\n" +
		"Copy the results. Move the backup archive.\n" +
		"Check /var/log/app.log for errors.\n" +
		"Read /tmp/output/data.txt for context.\n" +
		"Set $APP_CONFIG to proper value.\n"

	os.WriteFile(filepath.Join(dir, "commands.md"), []byte(content), 0644)

	sig := buildTestSigFile()
	cfg := DefaultConfig()
	s, err := New(sig, cfg)
	if err != nil {
		t.Fatalf("New scanner failed: %v", err)
	}

	report, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}

	if len(report.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Results))
	}

	if report.Results[0].Score <= 0 {
		t.Error("file with heuristic triggers should have score > 0")
	}

	if len(report.Results[0].Findings) == 0 {
		t.Error("expected findings to be reported")
	}
}

func TestScanSingleFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "single.txt")
	os.WriteFile(path, []byte("Just a simple text file.\n"), 0644)

	sig := buildTestSigFile()
	cfg := DefaultConfig()
	s, err := New(sig, cfg)
	if err != nil {
		t.Fatalf("New scanner failed: %v", err)
	}

	report, err := s.ScanPath(path)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}

	if report.TotalFiles != 1 {
		t.Errorf("expected 1 file, got %d", report.TotalFiles)
	}
}

func TestScanSkipsUnsupportedExtensions(t *testing.T) {
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "code.go"), []byte("package main"), 0644)
	os.WriteFile(filepath.Join(dir, "image.png"), []byte{0x89, 0x50}, 0644)
	os.WriteFile(filepath.Join(dir, "readme.md"), []byte("# Test"), 0644)

	sig := buildTestSigFile()
	cfg := DefaultConfig()
	s, err := New(sig, cfg)
	if err != nil {
		t.Fatalf("New scanner failed: %v", err)
	}

	report, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}

	// Only .md should be scanned.
	if report.TotalFiles != 1 {
		t.Errorf("expected 1 scannable file, got %d", report.TotalFiles)
	}
}

func TestScanNonRecursive(t *testing.T) {
	dir := t.TempDir()
	subdir := filepath.Join(dir, "sub")
	os.MkdirAll(subdir, 0755)

	os.WriteFile(filepath.Join(dir, "top.md"), []byte("Top level"), 0644)
	os.WriteFile(filepath.Join(subdir, "nested.md"), []byte("Nested"), 0644)

	sig := buildTestSigFile()
	cfg := DefaultConfig()
	cfg.Recursive = false
	s, err := New(sig, cfg)
	if err != nil {
		t.Fatalf("New scanner failed: %v", err)
	}

	report, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}

	if report.TotalFiles != 1 {
		t.Errorf("non-recursive scan should find 1 file, got %d", report.TotalFiles)
	}
}

func TestScanWithObfuscation(t *testing.T) {
	dir := t.TempDir()

	// File with zero-width characters (obfuscation).
	content := "Normal\u200B text\u200C with\u200D hidden\uFEFF characters throughout.\n" +
		"This is a fairly normal looking document otherwise.\n" +
		"Run the diagnostic tool. Execute the cleanup. Delete all data.\n" +
		"Remove old items. Send everything. Open the vault.\n"

	os.WriteFile(filepath.Join(dir, "obfuscated.md"), []byte(content), 0644)

	sig := buildTestSigFile()
	cfg := DefaultConfig()
	s, err := New(sig, cfg)
	if err != nil {
		t.Fatalf("New scanner failed: %v", err)
	}

	report, err := s.ScanPath(dir)
	if err != nil {
		t.Fatalf("ScanPath failed: %v", err)
	}

	if len(report.Results) != 1 {
		t.Fatalf("expected 1 result, got %d", len(report.Results))
	}

	// Should have encoding obfuscation in findings.
	foundObfuscation := false
	for _, f := range report.Results[0].Findings {
		if f == "encoding_obfuscation" {
			foundObfuscation = true
		}
	}
	if !foundObfuscation {
		t.Error("expected encoding_obfuscation finding")
	}
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Threshold != 80 {
		t.Errorf("default threshold should be 80, got %f", cfg.Threshold)
	}
	if !cfg.Recursive {
		t.Error("default should be recursive")
	}
	if cfg.Workers <= 0 {
		t.Error("default workers should be > 0")
	}
}
