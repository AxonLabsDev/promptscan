// PromptScan - Static prompt injection scanner.
// Scans text files for suspicious content before AI agents read them.
//
// Usage:
//   promptscan scan <path> [flags]
//   promptscan verify <sigfile>
//   promptscan version
package main

import (
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/AxonLabsDev/promptscan/internal/reporter"
	"github.com/AxonLabsDev/promptscan/internal/scanner"
	"github.com/AxonLabsDev/promptscan/internal/sigfile"
)

const version = "v0.1.0"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "scan":
		cmdScan(os.Args[2:])
	case "verify":
		cmdVerify(os.Args[2:])
	case "version":
		fmt.Printf("PromptScan %s\n", version)
	case "help", "--help", "-h":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func cmdScan(args []string) {
	cfg := scanner.DefaultConfig()
	jsonOutput := false
	quiet := false
	sigPath := ""
	hmacKeyStr := ""
	verbose := false
	var scanPaths []string

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "-r", "--recursive":
			cfg.Recursive = true
		case "-t", "--threshold":
			if i+1 < len(args) {
				i++
				v, err := strconv.ParseFloat(args[i], 64)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Invalid threshold: %s\n", args[i])
					os.Exit(1)
				}
				cfg.Threshold = v
			}
		case "--json":
			jsonOutput = true
		case "--quiet", "-q":
			quiet = true
		case "--sigfile":
			if i+1 < len(args) {
				i++
				sigPath = args[i]
			}
		case "-v", "--verbose":
			verbose = true
			cfg.Verbose = true
		case "--key":
			if i+1 < len(args) {
				i++
				hmacKeyStr = args[i]
			}
		default:
			if strings.HasPrefix(args[i], "-") {
				fmt.Fprintf(os.Stderr, "Unknown flag: %s\n", args[i])
				os.Exit(1)
			}
			scanPaths = append(scanPaths, args[i])
		}
	}

	if len(scanPaths) == 0 {
		fmt.Fprintln(os.Stderr, "Error: no scan path specified")
		fmt.Fprintln(os.Stderr, "Usage: promptscan scan <path> [flags]")
		os.Exit(1)
	}

	// Load signature file.
	if sigPath == "" {
		// Try default locations.
		candidates := []string{
			"signatures/default.pgsig",
			"/usr/local/share/promptscan/default.pgsig",
		}
		for _, c := range candidates {
			if _, err := os.Stat(c); err == nil {
				sigPath = c
				break
			}
		}
	}

	if sigPath == "" {
		fmt.Fprintln(os.Stderr, "Error: no signature file found. Use --sigfile to specify one.")
		fmt.Fprintln(os.Stderr, "Generate one with: promptscan-compile -i patterns.txt -o signatures/default.pgsig")
		os.Exit(1)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Loading signature file: %s\n", sigPath)
	}

	sig, err := sigfile.LoadFile(sigPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading signature file: %v\n", err)
		os.Exit(1)
	}

	// Verify HMAC integrity before scanning
	// Priority: --key flag > PROMPTSCAN_HMAC_KEY env > default
	hmacKey := []byte("promptscan-default-hmac-key-v1")
	if hmacKeyStr != "" {
		hmacKey = []byte(hmacKeyStr)
	} else if envKey := os.Getenv("PROMPTSCAN_HMAC_KEY"); envKey != "" {
		hmacKey = []byte(envKey)
	}
	if err := sigfile.Verify(sigPath, hmacKey); err != nil {
		fmt.Fprintf(os.Stderr, "WARNING: Signature file HMAC verification failed: %v\n", err)
		fmt.Fprintf(os.Stderr, "The signature file may be corrupted or tampered with.\n")
		os.Exit(1)
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "Signature file loaded and verified: %d hashes, bloom size %d bits\n",
			len(sig.HashTable), sig.Header.BloomSize)
	}

	s, err := scanner.New(sig, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating scanner: %v\n", err)
		os.Exit(1)
	}

	// Scan all paths and merge results.
	var allResults []reporter.FileResult
	totalFiles := 0
	var firstReport reporter.ScanReport

	for _, path := range scanPaths {
		report, err := s.ScanPath(path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error scanning %s: %v\n", path, err)
			continue
		}
		if totalFiles == 0 {
			firstReport = report
		}
		totalFiles += report.TotalFiles
		allResults = append(allResults, report.Results...)
	}

	firstReport.TotalFiles = totalFiles
	firstReport.Results = allResults

	if jsonOutput {
		if err := reporter.PrintJSON(os.Stdout, firstReport); err != nil {
			fmt.Fprintf(os.Stderr, "Error writing JSON: %v\n", err)
			os.Exit(1)
		}
	} else {
		reporter.PrintConsole(os.Stdout, firstReport, quiet)
	}

	// Exit code based on findings.
	hasBlocked := false
	for _, r := range allResults {
		if r.Severity == reporter.Blocked {
			hasBlocked = true
			break
		}
	}
	if hasBlocked {
		os.Exit(2)
	}
}

func cmdVerify(args []string) {
	if len(args) < 1 {
		fmt.Fprintln(os.Stderr, "Usage: promptscan verify <sigfile> [--key KEY]")
		os.Exit(1)
	}

	path := args[0]
	hmacKey := []byte("promptscan-default-hmac-key-v1") // default key

	for i := 1; i < len(args); i++ {
		if args[i] == "--key" && i+1 < len(args) {
			i++
			hmacKey = []byte(args[i])
		}
	}

	err := sigfile.Verify(path, hmacKey)
	if err != nil {
		fmt.Fprintf(os.Stderr, "FAILED: %v\n", err)
		os.Exit(1)
	}

	fmt.Println("OK: signature file integrity verified")
}

func printUsage() {
	fmt.Println(`PromptScan ` + version + ` - Static prompt injection scanner

Usage:
  promptscan scan <path> [flags]    Scan files for suspicious content
  promptscan verify <sigfile>       Verify signature file integrity
  promptscan version                Print version

Scan Flags:
  -r, --recursive     Scan directories recursively (default: true)
  -t, --threshold N   Block threshold score (default: 80)
  --json              Output results as JSON
  -q, --quiet         Only show findings with score > 20
  --sigfile PATH      Path to custom signature file (.pgsig)
  --key KEY           HMAC key for sigfile verification (env: PROMPTSCAN_HMAC_KEY)
  -v, --verbose       Enable verbose/debug output

Exit Codes:
  0    All files clean (score below block threshold)
  1    Error (bad arguments, missing files, etc.)
  2    Blocked files detected (score >= threshold)`)
}
