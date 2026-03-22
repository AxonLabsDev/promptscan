# PromptScan

> Detect prompt injection payloads in files **before** AI agents read them.

Static scanner that analyzes text files for manipulation patterns without ever storing those patterns in clear text. Zero false blocks on real-world system prompts.

[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Go](https://img.shields.io/badge/Go-1.25+-blue.svg)](https://go.dev)
[![Tests](https://img.shields.io/badge/Tests-45%20passed-brightgreen.svg)]()

---

## Why

AI agents (Claude Code, Codex, Gemini) read files as part of their workflow — skills, configs, documentation. A file containing manipulation instructions can hijack the agent into executing dangerous commands. This happened in production: a `.md` file caused an agent to overwrite `/etc/passwd`.

PromptScan catches these files before agents read them.

---

## Install

**From source:**

```bash
git clone https://github.com/AxonLabsDev/promptscan.git
cd promptscan
make build
make install   # copies to /usr/local/bin/
```

**Or with Go:**

```bash
go install github.com/AxonLabsDev/promptscan/cmd/promptscan@latest
```

---

## Quick Start

```bash
promptscan scan ./my-project/              # Scan a directory
promptscan scan ./skills/ -r               # Recursive
promptscan scan ./repo/ -t 60              # Custom threshold (default: 80)
promptscan scan ./docs/ --json             # JSON output for CI/CD
promptscan scan ./content/ -q              # Quiet (only findings > 20)
promptscan scan ./code/ --key mykey        # Custom HMAC key
promptscan verify signatures/default.pgsig # Verify signature integrity
promptscan version                         # Print version
```

---

## How It Works

Three detection levels, all under 50ms per file:

### Level 1 — Bloom Filter Pre-screen (< 1ms)
Fast probabilistic check on multi-size n-grams (4, 5, 6 words). Eliminates ~99% of clean files immediately. No false negatives.

### Level 2 — Hash Matching (< 10ms)
SHA-256 salted hashes of whole normalized lines. Binary search against a sorted hash table in the `.pgsig` signature file. A match means an exact known-bad phrase was found.

### Level 3 — Structural Heuristics (< 40ms)
Analyzes document **structure**, not content. No payload in source code.

| Heuristic | What It Detects |
|-----------|----------------|
| Imperative ratio | Abnormally high ratio of command-like sentences |
| System targets | References to file paths, env vars, file operations |
| Role reassignment | Attempts to redefine agent identity or override prior instructions |
| Encoding obfuscation | base64 blobs, unicode escapes, zero-width chars, HTML entities in non-HTML |
| Register break | Sudden shift from descriptive to imperative tone |

### Pre-processing
All content is decoded before analysis: base64, unicode escapes, zero-width characters (U+200B/C/D, FEFF), HTML entities.

---

## Security Design

**No detection patterns exist in clear text anywhere in the source code.**

This is critical: if the scanner's source contained injection patterns, an AI agent reading the scanner's code could itself be injected. The paradox is resolved by:

- **Hashed signatures**: SHA-256 of normalized fragments, stored in binary `.pgsig` files
- **Bloom filter bits**: probabilistic, not reversible
- **Structural heuristics**: detect document structure, not specific phrases
- **HMAC integrity**: signature files are verified before every scan

The signature compiler (`promptscan-compile`) is a **separate private tool** that reads clear-text patterns and outputs the binary `.pgsig`. Only the `.pgsig` is distributed.

---

## Signature Database

The default `signatures/default.pgsig` contains **29,898 patterns** compiled from public datasets:

- [deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (HuggingFace)
- [Alignment-Lab-AI/Prompt-Injection-Test](https://huggingface.co/datasets/Alignment-Lab-AI/Prompt-Injection-Test) (HuggingFace)
- [Open-Prompt-Injection](https://github.com/liu00222/Open-Prompt-Injection) (GitHub)

You can compile your own signature database from private patterns:

```bash
promptscan-compile -i my-patterns.txt -o my-signatures.pgsig --key my-secret-key
```

---

## Scoring

| Score | Label | Action |
|-------|-------|--------|
| < 20 | Clean | No concerns |
| 20-50 | Warn | Minor indicators, review if sensitive |
| 50-80 | Suspect | Review recommended |
| >= 80 | Blocked | High confidence — do not let agents read this file |

Context multiplier: encoding obfuscation detected = score x2.0

---

## Configuration

Optional `.promptscan.yml`:

```yaml
threshold: 80
extensions:
  - .md
  - .yaml
  - .json
  - .txt
ignore:
  - "**/node_modules/**"
  - "**/.git/**"
```

---

## Integration

### BodAIGuard Hook (planned)
Pre-tool-use hook that scans files before AI agents read them:
```
PreToolUse:Read → promptscan → allow/block
```

### NervMap Module (planned)
Diagnostic rule `prompt-injection-detected` in infrastructure scans.

### CI/CD
```bash
promptscan scan ./repo/ --json -t 60 || exit 1
```

---

## Exit Codes

| Code | Meaning |
|------|---------|
| 0 | All files clean (score below threshold) |
| 1 | Error (bad arguments, missing files) |
| 2 | Blocked files detected (score >= threshold) |

---

## Requirements

- Go 1.25+ (build)
- Linux, macOS, or Windows
- No runtime dependencies (single static binary)

---

## Roadmap

- [ ] BodAIGuard integration (PreToolUse:Read hook)
- [ ] NervMap integration (diagnostic rule)
- [ ] Weighted hash signatures (per-pattern severity)
- [ ] `--watch` mode with inotify
- [ ] More datasets (Kaggle, PINT benchmark)
- [ ] Delimiter injection heuristic

---

## License

MIT — Copyright 2026 AxonLabsDev
