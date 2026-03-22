// Package decoder handles pre-processing of text content to reveal
// obfuscated payloads before detection analysis is applied.
package decoder

import (
	"encoding/base64"
	"html"
	"regexp"
	"strings"
	"unicode/utf8"
)

// ZeroWidthChars are Unicode characters that have no visible representation
// but can be used to hide content.
var ZeroWidthChars = []rune{
	'\u200B', // ZERO WIDTH SPACE
	'\u200C', // ZERO WIDTH NON-JOINER
	'\u200D', // ZERO WIDTH JOINER
	'\uFEFF', // ZERO WIDTH NO-BREAK SPACE / BOM
}

var (
	base64BlockRe  = regexp.MustCompile(`(?:^|[\s=])([A-Za-z0-9+/]{20,}={0,2})(?:[\s]|$)`)
	unicodeEscRe   = regexp.MustCompile(`\\u([0-9a-fA-F]{4})`)
	unicodeEscReU8 = regexp.MustCompile(`\\U([0-9a-fA-F]{8})`)
)

// Result holds the decoded content and metadata about what was found.
type Result struct {
	Content           string
	HasBase64         bool
	HasUnicodeEscapes bool
	HasZeroWidthChars bool
	HasHTMLEntities   bool
	Base64Decoded     []string // successfully decoded base64 segments
	ObfuscationScore  float64  // 0.0-1.0 indicating level of obfuscation
}

// Decode applies all decoding layers to the input text.
// isHTML indicates whether the source file is HTML (skip HTML entity decoding for those).
func Decode(text string, isHTML bool) Result {
	r := Result{Content: text}

	// 1. Detect and remove zero-width characters.
	r.Content, r.HasZeroWidthChars = removeZeroWidth(r.Content)

	// 2. Expand unicode escape sequences.
	r.Content, r.HasUnicodeEscapes = expandUnicodeEscapes(r.Content)

	// 3. Decode HTML entities (skip for actual HTML files).
	if !isHTML {
		r.Content, r.HasHTMLEntities = decodeHTMLEntities(r.Content)
	}

	// 4. Detect and decode base64 blobs.
	r.Content, r.HasBase64, r.Base64Decoded = decodeBase64Blobs(r.Content)

	// Calculate obfuscation score.
	score := 0.0
	if r.HasBase64 {
		score += 0.3
	}
	if r.HasUnicodeEscapes {
		score += 0.2
	}
	if r.HasZeroWidthChars {
		score += 0.3
	}
	if r.HasHTMLEntities {
		score += 0.2
	}
	r.ObfuscationScore = score

	return r
}

// removeZeroWidth strips zero-width Unicode characters from text.
func removeZeroWidth(s string) (string, bool) {
	found := false
	var b strings.Builder
	b.Grow(len(s))
	for _, r := range s {
		isZW := false
		for _, zw := range ZeroWidthChars {
			if r == zw {
				isZW = true
				found = true
				break
			}
		}
		if !isZW {
			b.WriteRune(r)
		}
	}
	return b.String(), found
}

// expandUnicodeEscapes replaces \uXXXX and \UXXXXXXXX sequences with their characters.
func expandUnicodeEscapes(s string) (string, bool) {
	found := false

	result := unicodeEscRe.ReplaceAllStringFunc(s, func(match string) string {
		sub := unicodeEscRe.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		var r rune
		for _, c := range sub[1] {
			r = r * 16
			switch {
			case c >= '0' && c <= '9':
				r += c - '0'
			case c >= 'a' && c <= 'f':
				r += c - 'a' + 10
			case c >= 'A' && c <= 'F':
				r += c - 'A' + 10
			}
		}
		if utf8.ValidRune(r) {
			found = true
			return string(r)
		}
		return match
	})

	result2 := unicodeEscReU8.ReplaceAllStringFunc(result, func(match string) string {
		sub := unicodeEscReU8.FindStringSubmatch(match)
		if len(sub) < 2 {
			return match
		}
		var r rune
		for _, c := range sub[1] {
			r = r * 16
			switch {
			case c >= '0' && c <= '9':
				r += c - '0'
			case c >= 'a' && c <= 'f':
				r += c - 'a' + 10
			case c >= 'A' && c <= 'F':
				r += c - 'A' + 10
			}
		}
		if utf8.ValidRune(r) {
			found = true
			return string(r)
		}
		return match
	})

	return result2, found
}

// decodeHTMLEntities unescapes HTML entities in non-HTML files.
func decodeHTMLEntities(s string) (string, bool) {
	decoded := html.UnescapeString(s)
	return decoded, decoded != s
}

// decodeBase64Blobs finds and decodes base64-encoded segments.
func decodeBase64Blobs(s string) (string, bool, []string) {
	matches := base64BlockRe.FindAllStringSubmatchIndex(s, -1)
	if len(matches) == 0 {
		return s, false, nil
	}

	var decoded []string
	found := false
	result := s

	// Process matches in reverse to preserve indices.
	for i := len(matches) - 1; i >= 0; i-- {
		m := matches[i]
		if len(m) < 4 {
			continue
		}
		start, end := m[2], m[3]
		encoded := result[start:end]

		raw, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			// Try RawStdEncoding (no padding).
			raw, err = base64.RawStdEncoding.DecodeString(strings.TrimRight(encoded, "="))
			if err != nil {
				continue
			}
		}

		// Only consider it valid base64 if the result is mostly printable text.
		if !isPrintableText(raw) {
			continue
		}

		found = true
		decodedStr := string(raw)
		decoded = append(decoded, decodedStr)
		// Append decoded content after the original (keep original for hash matching).
		result = result[:end] + " [decoded:" + decodedStr + "]" + result[end:]
	}

	return result, found, decoded
}

// isPrintableText checks if at least 80% of bytes are printable ASCII or valid UTF-8 text.
func isPrintableText(data []byte) bool {
	if len(data) == 0 {
		return false
	}
	printable := 0
	total := 0
	for i := 0; i < len(data); {
		r, size := utf8.DecodeRune(data[i:])
		total++
		if r != utf8.RuneError && (r >= 0x20 || r == '\n' || r == '\r' || r == '\t') {
			printable++
		}
		i += size
	}
	return float64(printable)/float64(total) >= 0.80
}
