// promptscan-compile generates .pgsig signature database files
// from a private pattern list. This tool is NOT distributed publicly.
//
// Usage:
//   promptscan-compile -i patterns.txt -o output.pgsig [-k hmac-key] [-s salt]
//
// The input file contains one detection pattern per line (clear text).
// The output is a binary .pgsig file containing only hashes and a bloom filter.
package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"strings"

	"github.com/AxonLabsDev/promptscan/internal/bloom"
	"github.com/AxonLabsDev/promptscan/internal/hasher"
	"github.com/AxonLabsDev/promptscan/internal/sigfile"
)

const version = "v0.1.0"

func main() {
	inputFile := ""
	outputFile := ""
	hmacKeyStr := "promptscan-default-hmac-key-v1"
	var customSalt []byte
	verbose := false

	args := os.Args[1:]
	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-i", "--input":
			if i+1 < len(args) {
				i++
				inputFile = args[i]
			}
		case "-o", "--output":
			if i+1 < len(args) {
				i++
				outputFile = args[i]
			}
		case "-k", "--key":
			if i+1 < len(args) {
				i++
				hmacKeyStr = args[i]
			}
		case "-s", "--salt":
			if i+1 < len(args) {
				i++
				customSalt = []byte(args[i])
			}
		case "-v", "--verbose":
			verbose = true
		case "--version":
			fmt.Printf("promptscan-compile %s\n", version)
			os.Exit(0)
		case "-h", "--help":
			printUsage()
			os.Exit(0)
		default:
			fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
			os.Exit(1)
		}
	}

	if inputFile == "" || outputFile == "" {
		fmt.Fprintln(os.Stderr, "Error: both -i (input) and -o (output) are required")
		printUsage()
		os.Exit(1)
	}

	// Generate or use salt.
	var salt [16]byte
	if customSalt != nil {
		copy(salt[:], customSalt)
	} else {
		if _, err := rand.Read(salt[:]); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating salt: %v\n", err)
			os.Exit(1)
		}
	}

	// Read patterns from input file.
	patterns, err := readPatterns(inputFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading patterns: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Read %d patterns from %s\n", len(patterns), inputFile)
	}

	if len(patterns) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no patterns found in input file")
		os.Exit(1)
	}

	// Estimate bloom filter size: each pattern produces ~9 n-grams on average
	// (3+4+5 word n-grams minus those too short) plus 1 line hash.
	estimatedItems := uint32(len(patterns) * 10)
	bf := bloom.New(estimatedItems, 0.001)

	var allHashes [][]byte
	totalNgrams := 0

	for _, pattern := range patterns {
		// N-grams go into bloom filter only (pre-screening).
		ngrams := hasher.MultiSizeNGrams(pattern)
		for _, ng := range ngrams {
			h := hasher.SaltedHash(ng, salt[:])
			bf.Add(h)
			totalNgrams++
		}

		// Whole-line hash goes into both bloom filter AND hash table (Level 2 matching).
		lineHash := hasher.SaltedHash(pattern, salt[:])
		bf.Add(lineHash)
		allHashes = append(allHashes, lineHash)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Generated %d n-gram hashes + %d line hashes\n", totalNgrams, len(patterns))
		fmt.Fprintf(os.Stderr, "Bloom filter: %d bits, %d hash functions\n", bf.Size(), bf.HashCount())
		fmt.Fprintf(os.Stderr, "Total unique hashes: %d\n", len(allHashes))
	}

	// Build signature file.
	sf := sigfile.New(1, salt, bf.Bytes(), bf.Size(), bf.HashCount(), allHashes)

	// Write output.
	hmacKey := []byte(hmacKeyStr)
	if err := sf.WriteFile(outputFile, hmacKey); err != nil {
		fmt.Fprintf(os.Stderr, "Error writing signature file: %v\n", err)
		os.Exit(1)
	}

	if verbose {
		info, _ := os.Stat(outputFile)
		fmt.Fprintf(os.Stderr, "Written: %s (%d bytes)\n", outputFile, info.Size())
	}

	fmt.Printf("Compiled %d patterns into %s\n", len(patterns), outputFile)
}

// readPatterns reads one pattern per line from a file.
// Empty lines and lines starting with # are skipped.
func readPatterns(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns, scanner.Err()
}

func printUsage() {
	fmt.Println(`promptscan-compile ` + version + ` - Signature database compiler

Compiles detection patterns into a binary .pgsig signature file.
This tool is NOT distributed publicly; only the .pgsig output is shared.

Usage:
  promptscan-compile -i <patterns.txt> -o <output.pgsig> [flags]

Flags:
  -i, --input PATH    Input pattern file (one per line, clear text)
  -o, --output PATH   Output .pgsig file
  -k, --key KEY       HMAC signing key (default: built-in)
  -s, --salt SALT     Custom salt (default: random)
  -v, --verbose       Verbose output
  --version           Print version
  -h, --help          Print this help

Pattern File Format:
  One detection pattern per line.
  Lines starting with # are comments.
  Empty lines are skipped.
  Patterns are normalized before hashing.`)
}
