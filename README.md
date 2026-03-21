# PromptScan

Static prompt injection scanner for text files. Scans `.md`, `.yaml`, `.json`, `.txt`, `.html`, `.xml`, `.toml`, `.env`, `.cfg`, `.ini`, `.conf` files for suspicious content **before** an AI agent reads them.

Reports each file with a risk score (0-100) based on three detection levels.

## Detection Architecture

### Level 1 - Bloom Filter Pre-filter (< 1ms/file)
Fast probabilistic check using multi-size n-gram hashing. Eliminates ~99% of clean files immediately.

### Level 2 - Hash Matching (< 10ms/file)
SHA-256 hash confirmation against a sorted hash table. Exact match of known detection signatures.

### Level 3 - Structural Heuristics (< 40ms/file)
No payload content in source code. Analyzes document structure:
- Imperative sentence ratio
- System target density (paths, env vars, file operations)
- Role reassignment structure detection
- Encoding obfuscation (base64, unicode escapes, zero-width chars, HTML entities)
- Register break (tonal shift from descriptive to imperative)

### Pre-processing
All content is decoded before analysis: base64, unicode escapes, zero-width characters, HTML entities.

## Security Design

**No detection patterns exist in clear text anywhere in the source code.** All signatures are stored as:
- SHA-256 hashes of normalized text fragments
- Bloom filter bits
- Structural heuristic rules (no payload content)

The signature database (`.pgsig`) is a binary file with HMAC-SHA256 integrity verification.

## Install

```bash
go install github.com/AxonLabsDev/promptscan/cmd/promptscan@latest
```

Or build from source:

```bash
make build
```

## Usage

```bash
# Scan a directory
promptscan scan ./docs/ --sigfile signatures/default.pgsig

# Recursive scan with custom threshold
promptscan scan ./project/ -r -t 60

# JSON output for CI/CD integration
promptscan scan ./repo/ --json --sigfile sigs.pgsig

# Quiet mode (only findings > 20)
promptscan scan ./content/ -q

# Verify signature file integrity
promptscan verify signatures/default.pgsig
```

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All files clean |
| 1 | Error (bad args, missing files) |
| 2 | Blocked files detected |

## Scoring

| Level | Score Range | Label |
|-------|------------|-------|
| Clean | < 20 | No concerns |
| Warn | 20-50 | Minor indicators |
| Suspect | 50-80 | Review recommended |
| Blocked | >= 80 | High confidence detection |

Context multipliers: encoding obfuscation detected = score x2.0

## Signature Compiler (Private)

The `promptscan-compile` tool generates `.pgsig` files from clear-text pattern lists. It is **not distributed publicly**; only the compiled `.pgsig` output is shipped.

```bash
promptscan-compile -i patterns.txt -o default.pgsig -v
```

## License

MIT - AxonLabsDev
