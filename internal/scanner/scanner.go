// Package scanner orchestrates the three-level detection pipeline
// for scanning files against known detection signatures.
package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AxonLabsDev/promptscan/internal/bloom"
	"github.com/AxonLabsDev/promptscan/internal/decoder"
	"github.com/AxonLabsDev/promptscan/internal/hasher"
	"github.com/AxonLabsDev/promptscan/internal/heuristics"
	"github.com/AxonLabsDev/promptscan/internal/reporter"
	"github.com/AxonLabsDev/promptscan/internal/sigfile"
)

// SupportedExtensions lists the file types that are scanned.
var SupportedExtensions = map[string]bool{
	".md":   true,
	".yaml": true,
	".yml":  true,
	".json": true,
	".txt":  true,
	".html": true,
	".xml":  true,
	".toml": true,
	".env":  true,
	".cfg":  true,
	".ini":  true,
	".conf": true,
}

// Config holds scanner configuration.
type Config struct {
	Recursive      bool
	Threshold      float64
	Verbose        bool
	MaxFileSize    int64 // bytes, default 10MB
	Workers        int
}

// DefaultConfig returns reasonable default configuration.
func DefaultConfig() Config {
	return Config{
		Recursive:   true,
		Threshold:   80,
		Verbose:     false,
		MaxFileSize: 10 * 1024 * 1024, // 10MB
		Workers:     8,
	}
}

// Scanner performs file scanning using the three-level detection pipeline.
type Scanner struct {
	config Config
	sig    *sigfile.SigFile
	bloom  *bloom.Filter
}

// New creates a Scanner with the given signature file and config.
func New(sig *sigfile.SigFile, cfg Config) (*Scanner, error) {
	// Reconstruct bloom filter from signature data.
	bf, err := bloom.NewFromRaw(sig.BloomData, sig.Header.BloomSize, sig.Header.HashCount)
	if err != nil {
		return nil, err
	}

	return &Scanner{
		config: cfg,
		sig:    sig,
		bloom:  bf,
	}, nil
}

// ScanPath scans a file or directory and returns a report.
func (s *Scanner) ScanPath(path string) (reporter.ScanReport, error) {
	start := time.Now()

	files, err := s.collectFiles(path)
	if err != nil {
		return reporter.ScanReport{}, err
	}

	results := s.scanFiles(files)

	report := reporter.ScanReport{
		Version:    "v0.1.0",
		ScannedAt:  start,
		TotalFiles: len(files),
		Duration:   time.Since(start),
		Threshold:  s.config.Threshold,
		Results:    results,
	}

	return report, nil
}

// collectFiles gathers all scannable files under a path.
func (s *Scanner) collectFiles(path string) ([]string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, err
	}

	if !info.IsDir() {
		ext := strings.ToLower(filepath.Ext(path))
		if SupportedExtensions[ext] {
			return []string{path}, nil
		}
		return nil, nil
	}

	var files []string
	walkFn := func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // skip errors
		}
		if d.IsDir() {
			if !s.config.Recursive && p != path {
				return filepath.SkipDir
			}
			// Skip hidden directories.
			if strings.HasPrefix(d.Name(), ".") && p != path {
				return filepath.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(p))
		if !SupportedExtensions[ext] {
			return nil
		}

		// Check file size.
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > s.config.MaxFileSize {
			return nil
		}

		files = append(files, p)
		return nil
	}

	err = filepath.WalkDir(path, walkFn)
	return files, err
}

// scanFiles processes files concurrently.
func (s *Scanner) scanFiles(files []string) []reporter.FileResult {
	results := make([]reporter.FileResult, len(files))
	var wg sync.WaitGroup

	sem := make(chan struct{}, s.config.Workers)

	for i, f := range files {
		wg.Add(1)
		go func(idx int, filePath string) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			results[idx] = s.scanFile(filePath)
		}(i, f)
	}

	wg.Wait()
	return results
}

// scanFile runs the three-level pipeline on a single file.
func (s *Scanner) scanFile(path string) reporter.FileResult {
	result := reporter.FileResult{Path: path}

	content, err := os.ReadFile(path)
	if err != nil {
		return result
	}

	text := string(content)
	ext := strings.ToLower(filepath.Ext(path))
	isHTML := ext == ".html" || ext == ".htm"

	// Pre-processing: decode layer.
	decoded := decoder.Decode(text, isHTML)

	// Context multiplier for obfuscation.
	obfuscationMultiplier := 1.0
	if decoded.ObfuscationScore > 0 {
		obfuscationMultiplier = 1.0 + decoded.ObfuscationScore
	}

	score := 0.0
	var findings []string

	// Level 1: Bloom filter pre-check using multi-size n-grams.
	bloomHit := false
	ngrams := hasher.MultiSizeNGrams(decoded.Content)
	salt := s.sig.Header.Salt[:]
	for _, ng := range ngrams {
		h := hasher.SaltedHash(ng, salt)
		if s.bloom.Test(h) {
			bloomHit = true
			break
		}
	}

	// Level 2: Hash matching (only if bloom says possible hit).
	if bloomHit {
		hashMatches := 0
		// Check line-level hashes.
		lines := strings.Split(decoded.Content, "\n")
		for lineIdx, line := range lines {
			normalized := hasher.Normalize(line)
			if normalized == "" {
				continue
			}
			h := hasher.SaltedHash(line, salt)
			if s.sig.LookupHash(h) {
				hashMatches++
				if result.Line == 0 {
					result.Line = lineIdx + 1
				}
			}
			// Also check n-grams of each line.
			lineGrams := hasher.MultiSizeNGrams(line)
			for _, ng := range lineGrams {
				h := hasher.SaltedHash(ng, salt)
				if s.sig.LookupHash(h) {
					hashMatches++
					if result.Line == 0 {
						result.Line = lineIdx + 1
					}
				}
			}
		}

		if hashMatches > 0 {
			score += float64(hashMatches) * 3.0
			findings = append(findings, formatHashMatch(hashMatches))
		}
	}

	// Level 3: Structural heuristics (always runs).
	hResult := heuristics.Analyze(decoded.Content, filepath.Base(path))
	for _, f := range hResult.Findings {
		score += f.Score
		findings = append(findings, f.Detail)
	}

	// Add encoding obfuscation finding.
	if decoded.ObfuscationScore > 0 {
		findings = append(findings, "encoding_obfuscation")
	}

	// Apply obfuscation multiplier.
	score *= obfuscationMultiplier

	// Cap at 100.
	if score > 100 {
		score = 100
	}

	result.Score = score
	result.Severity = reporter.Classify(score, s.config.Threshold)
	result.Findings = findings

	return result
}

func formatHashMatch(count int) string {
	s := "hash_match("
	if count == 0 {
		return s + "0)"
	}
	digits := make([]byte, 0, 10)
	n := count
	for n > 0 {
		digits = append(digits, byte('0'+n%10))
		n /= 10
	}
	for i, j := 0, len(digits)-1; i < j; i, j = i+1, j-1 {
		digits[i], digits[j] = digits[j], digits[i]
	}
	return s + string(digits) + ")"
}
