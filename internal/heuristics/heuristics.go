// Package heuristics performs structural analysis of text to detect
// suspicious patterns without containing any detection payloads.
// All analysis is based on document structure, not content matching.
package heuristics

import (
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode"

	"github.com/AxonLabsDev/promptscan/internal/hasher"
)

// Finding represents a single heuristic detection result.
type Finding struct {
	Rule   string  // rule identifier
	Score  float64 // contribution to total score
	Detail string  // human-readable description (structural, no payload content)
}

// Result holds all heuristic findings for a piece of content.
type Result struct {
	Findings []Finding
	Total    float64
}

// Analyze runs all structural heuristics on the given content.
func Analyze(content string, fileName string) Result {
	var r Result

	r.addFindings(imperativeRatio(content))
	r.addFindings(systemTargetDensity(content))
	r.addFindings(roleReassignment(content))
	r.addFindings(encodingDetection(content, fileName))
	r.addFindings(registerBreak(content))

	return r
}

func (r *Result) addFindings(findings []Finding) {
	for _, f := range findings {
		r.Findings = append(r.Findings, f)
		r.Total += f.Score
	}
}

// imperativeRatio measures the proportion of sentences that begin with
// imperative verb structures. A high ratio suggests instructional/command content.
func imperativeRatio(content string) []Finding {
	sentences := hasher.Tokenize(content)
	if len(sentences) < 3 {
		return nil
	}

	imperative := 0
	for _, s := range sentences {
		if hasher.IsImperativeStart(s) {
			imperative++
		}
	}

	ratio := float64(imperative) / float64(len(sentences))
	if ratio < 0.4 {
		return nil
	}

	score := ratio * 5.0 // max 5.0
	return []Finding{{
		Rule:   "imperative_ratio",
		Score:  math.Min(score, 5.0),
		Detail: formatFloat("imperative_ratio", ratio),
	}}
}

// systemTargetDensity counts references to system-level constructs:
// file paths, environment variables, configuration patterns, file operation keywords.
// Uses structural patterns (path-like strings, $VAR patterns) not specific names.
var (
	// Structural patterns for system references (no specific names).
	unixPathRe = regexp.MustCompile(`(?:^|[\s"'])(/(?:etc|var|usr|tmp|opt|home|root|proc|sys|dev|bin|sbin)/[a-zA-Z0-9_./-]+)`)
	winPathRe  = regexp.MustCompile(`(?i)(?:^|[\s"'])[a-zA-Z]:\\[a-zA-Z0-9\\._-]+`)
	envVarRe   = regexp.MustCompile(`\$\{?[A-Z_][A-Z0-9_]{2,}\}?`)
	// File operation structural indicators (verb + path-like argument).
	fileOpStructureRe = regexp.MustCompile(`(?i)(?:read|write|open|delete|remove|create|modify|execute|chmod|chown|curl|wget|fetch)\s+[/"'\$]`)
)

func systemTargetDensity(content string) []Finding {
	lines := strings.Split(content, "\n")
	totalLines := len(lines)
	if totalLines == 0 {
		return nil
	}

	hits := 0
	hits += len(unixPathRe.FindAllString(content, -1))
	hits += len(winPathRe.FindAllString(content, -1))
	hits += len(envVarRe.FindAllString(content, -1))
	hits += len(fileOpStructureRe.FindAllString(content, -1))

	if hits < 3 {
		return nil
	}

	density := float64(hits) / float64(totalLines)
	score := math.Min(density*2.0, 2.0)
	if hits >= 5 {
		score = math.Min(score+0.5, 2.0)
	}

	return []Finding{{
		Rule:   "system_targets",
		Score:  score,
		Detail: formatDetail("system_targets", hits),
	}}
}

// roleReassignment detects structural patterns of identity/role override attempts.
// Looks for structural indicators: sentences that structurally assign a new role
// (subject + copula + role-like object) or override instruction patterns
// (structural negation + previous reference + new directive).
var (
	// Structural: "you are [now] [a/the] ..." pattern (copula + role assignment).
	roleAssignRe = regexp.MustCompile(`(?i)(?:^|\n)\s*you\s+are\s+(?:now\s+)?(?:a\s+|the\s+|an\s+)?[a-z]+`)
	// Structural: "from now on" + directive.
	newDirectiveRe = regexp.MustCompile(`(?i)from\s+now\s+on`)
	// Structural: negation of prior instructions.
	priorNegationRe = regexp.MustCompile(`(?i)(?:ignore|disregard|forget|override|bypass)\s+(?:all\s+)?(?:previous|prior|above|earlier|original|old)`)
	// Structural: "your new" + role/instruction word.
	newRoleRe = regexp.MustCompile(`(?i)your\s+new\s+(?:role|instructions?|purpose|task|objective|mission|identity|persona|name)`)
	// Structural: explicit system/user/assistant section markers.
	sectionMarkerRe = regexp.MustCompile(`(?i)(?:^|\n)\s*(?:\[?\s*(?:system|assistant|user)\s*(?:message|prompt|instruction)?\s*\]?\s*:)`)
)

func roleReassignment(content string) []Finding {
	var findings []Finding

	if matches := roleAssignRe.FindAllString(content, -1); len(matches) > 0 {
		findings = append(findings, Finding{
			Rule:   "role_reassignment",
			Score:  5.0,
			Detail: formatDetail("role_assign_structure", len(matches)),
		})
	}

	directives := 0
	directives += len(newDirectiveRe.FindAllString(content, -1))
	directives += len(priorNegationRe.FindAllString(content, -1))
	directives += len(newRoleRe.FindAllString(content, -1))
	directives += len(sectionMarkerRe.FindAllString(content, -1))

	if directives > 0 {
		score := math.Min(float64(directives)*3.0, 10.0)
		findings = append(findings, Finding{
			Rule:   "role_reassignment",
			Score:  score,
			Detail: formatDetail("directive_override_structure", directives),
		})
	}

	return findings
}

// encodingDetection identifies obfuscation techniques in content.
// Looks for base64 blocks, unicode escapes, zero-width characters,
// and HTML entities in non-HTML files.
var (
	base64LongBlockRe = regexp.MustCompile(`[A-Za-z0-9+/]{40,}={0,2}`)
	unicodeEscapeRe   = regexp.MustCompile(`\\u[0-9a-fA-F]{4}`)
	htmlEntityRe      = regexp.MustCompile(`&(?:#[0-9]+|#x[0-9a-fA-F]+|[a-zA-Z]+);`)
)

func encodingDetection(content string, fileName string) []Finding {
	isHTML := strings.HasSuffix(strings.ToLower(fileName), ".html") ||
		strings.HasSuffix(strings.ToLower(fileName), ".htm")

	var findings []Finding

	// Large base64 blocks.
	b64Matches := base64LongBlockRe.FindAllString(content, -1)
	if len(b64Matches) > 0 {
		findings = append(findings, Finding{
			Rule:   "encoding_detected",
			Score:  3.0,
			Detail: formatDetail("base64_blocks", len(b64Matches)),
		})
	}

	// Unicode escape sequences.
	uniMatches := unicodeEscapeRe.FindAllString(content, -1)
	if len(uniMatches) >= 3 {
		findings = append(findings, Finding{
			Rule:   "encoding_detected",
			Score:  0.8,
			Detail: formatDetail("unicode_escapes", len(uniMatches)),
		})
	}

	// HTML entities in non-HTML files.
	if !isHTML {
		htmlMatches := htmlEntityRe.FindAllString(content, -1)
		if len(htmlMatches) >= 5 {
			findings = append(findings, Finding{
				Rule:   "encoding_detected",
				Score:  0.5,
				Detail: formatDetail("html_entities_in_non_html", len(htmlMatches)),
			})
		}
	}

	// Zero-width character check (by counting invisible Unicode categories).
	zwCount := 0
	for _, r := range content {
		if r == '\u200B' || r == '\u200C' || r == '\u200D' || r == '\uFEFF' {
			zwCount++
		} else if unicode.Is(unicode.Cf, r) && r != '\n' && r != '\r' && r != '\t' {
			// Other invisible format characters (not already counted above)
			zwCount++
		}
	}
	if zwCount > 0 {
		findings = append(findings, Finding{
			Rule:   "encoding_detected",
			Score:  5.0,
			Detail: formatDetail("zero_width_chars", zwCount),
		})
	}

	return findings
}

// registerBreak detects sudden tonal shifts from descriptive to imperative
// by measuring the sentence-level transition pattern.
func registerBreak(content string) []Finding {
	sentences := hasher.Tokenize(content)
	if len(sentences) < 6 {
		return nil
	}

	// Classify each sentence as imperative or descriptive.
	types := make([]bool, len(sentences)) // true = imperative
	for i, s := range sentences {
		types[i] = hasher.IsImperativeStart(s)
	}

	// Look for transition zones: a run of descriptive sentences followed by
	// a run of imperative sentences (minimum 3 each).
	maxTransitionScore := 0.0
	for i := 3; i < len(types)-2; i++ {
		// Count descriptive before i.
		descBefore := 0
		for j := i - 1; j >= 0 && j >= i-5; j-- {
			if !types[j] {
				descBefore++
			}
		}
		// Count imperative from i onward.
		impAfter := 0
		for j := i; j < len(types) && j < i+5; j++ {
			if types[j] {
				impAfter++
			}
		}

		if descBefore >= 3 && impAfter >= 3 {
			transition := float64(descBefore+impAfter) / 10.0
			if transition > maxTransitionScore {
				maxTransitionScore = transition
			}
		}
	}

	if maxTransitionScore < 0.5 {
		return nil
	}

	score := math.Min(maxTransitionScore*8.0, 8.0)
	return []Finding{{
		Rule:   "register_break",
		Score:  score,
		Detail: formatFloat("tonal_shift_score", maxTransitionScore),
	}}
}

func formatDetail(rule string, count int) string {
	return rule + "(" + itoa(count) + ")"
}

func formatFloat(rule string, val float64) string {
	s := rule + "("
	// Simple float formatting to 2 decimal places.
	whole := int(val)
	frac := int((val - float64(whole)) * 100)
	if frac < 0 {
		frac = -frac
	}
	s += itoa(whole) + "."
	if frac < 10 {
		s += "0"
	}
	s += itoa(frac) + ")"
	return s
}

func itoa(n int) string {
	return strconv.Itoa(n)
}
