# PromptScan

> Detect prompt injection payloads in files **before** AI agents read them.

Static scanner that analyzes text files for manipulation patterns. Zero false blocks on real-world system prompts.

[![License](https://img.shields.io/badge/License-Proprietary-red.svg)]()
[![Platforms](https://img.shields.io/badge/Platforms-Linux%20|%20macOS%20|%20Windows-blue.svg)]()

---

## Why

AI agents (Claude Code, Codex, Gemini) read files as part of their workflow. A file containing manipulation instructions can hijack the agent into executing dangerous commands.

PromptScan catches these files before agents read them.

---

## Install

Download the binary for your platform from [Releases](https://github.com/AxonLabsDev/promptscan/releases), then:

```bash
# Linux
chmod +x promptscan-linux-amd64
sudo mv promptscan-linux-amd64 /usr/local/bin/promptscan

# macOS (Apple Silicon)
chmod +x promptscan-darwin-arm64
sudo mv promptscan-darwin-arm64 /usr/local/bin/promptscan

# macOS (Intel)
chmod +x promptscan-darwin-amd64
sudo mv promptscan-darwin-amd64 /usr/local/bin/promptscan
```

Download `default.pgsig` and place it in `./signatures/` or `/usr/local/share/promptscan/`.

---

## Usage

```bash
promptscan scan ./my-project/              # Scan a directory
promptscan scan ./skills/ -r               # Recursive
promptscan scan ./repo/ -t 60              # Custom threshold (default: 80)
promptscan scan ./docs/ --json             # JSON output for CI/CD
promptscan scan ./content/ -q              # Quiet (only findings > 20)
promptscan verify signatures/default.pgsig # Verify signature integrity
promptscan version                         # Print version
```

---

## How It Works

Three detection levels, all under 50ms per file:

| Level | Technique | Speed |
|-------|-----------|-------|
| 1 | Bloom filter pre-screen on n-grams | < 1ms |
| 2 | SHA-256 hash matching on whole lines | < 10ms |
| 3 | Structural heuristics (no payload content) | < 40ms |

### Structural Heuristics

| Heuristic | What It Detects |
|-----------|----------------|
| Imperative ratio | Abnormally high ratio of command-like sentences |
| System targets | References to file paths, env vars, file operations |
| Role reassignment | Attempts to redefine agent identity or override instructions |
| Encoding obfuscation | base64, unicode escapes, zero-width chars, HTML entities |
| Register break | Sudden shift from descriptive to imperative tone |

### Pre-processing

All content is decoded before analysis: base64, unicode escapes, zero-width characters, HTML entities.

---

## Security Design

**No detection patterns exist in clear text in the binary.** All signatures are stored as SHA-256 hashes in a binary `.pgsig` format with HMAC-SHA256 integrity verification.

---

## Signature Database

The default `default.pgsig` contains **29,898 patterns** compiled from public research datasets.

---

## Scoring

| Score | Label | Action |
|-------|-------|--------|
| < 20 | Clean | No concerns |
| 20-50 | Warn | Minor indicators |
| 50-80 | Suspect | Review recommended |
| >= 80 | Blocked | Do not let agents read this file |

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All files clean |
| 1 | Error |
| 2 | Blocked files detected |

---

## Platforms

- Linux (amd64, arm64)
- macOS (amd64, arm64)
- Windows (amd64)

Single static binary, no runtime dependencies.

---

## License

Proprietary — Copyright 2026 AxonLabsDev. All rights reserved.

Free for personal and non-commercial use. Contact for commercial licensing.
