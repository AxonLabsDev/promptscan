// Package hasher handles text normalization and cryptographic hashing
// for consistent signature matching across varied input formats.
package hasher

import (
	"crypto/sha256"
	"regexp"
	"strings"
	"unicode"

	"golang.org/x/text/unicode/norm"
)

var (
	whitespaceRe  = regexp.MustCompile(`\s+`)
	punctuationRe = regexp.MustCompile(`[^\p{L}\p{N}\s]`)
)

// Normalize applies the standard normalization pipeline:
// NFKC unicode normalization, lowercase, strip punctuation, collapse whitespace, trim.
func Normalize(s string) string {
	// NFKC normalization
	s = norm.NFKC.String(s)
	// Lowercase
	s = strings.ToLower(s)
	// Strip punctuation (keep letters, numbers, whitespace)
	s = punctuationRe.ReplaceAllString(s, " ")
	// Collapse whitespace
	s = whitespaceRe.ReplaceAllString(s, " ")
	// Trim
	s = strings.TrimSpace(s)
	return s
}

// HashSHA256 returns the SHA-256 digest of the input bytes.
func HashSHA256(data []byte) []byte {
	h := sha256.Sum256(data)
	return h[:]
}

// HashNormalized normalizes the string then returns its SHA-256 digest.
func HashNormalized(s string) []byte {
	return HashSHA256([]byte(Normalize(s)))
}

// SaltedHash returns SHA-256(salt + normalized(s)).
func SaltedHash(s string, salt []byte) []byte {
	n := Normalize(s)
	data := make([]byte, len(salt)+len(n))
	copy(data, salt)
	copy(data[len(salt):], []byte(n))
	return HashSHA256(data)
}

// NGrams splits normalized text into word n-grams of the given size.
func NGrams(text string, n int) []string {
	words := strings.Fields(Normalize(text))
	if len(words) < n {
		return nil
	}
	grams := make([]string, 0, len(words)-n+1)
	for i := 0; i <= len(words)-n; i++ {
		grams = append(grams, strings.Join(words[i:i+n], " "))
	}
	return grams
}

// DefaultNGramSizes are the n-gram sizes used for detection.
// Larger n-grams reduce false positives on common phrases.
var DefaultNGramSizes = []int{4, 5, 6}

// MultiSizeNGrams generates n-grams of multiple sizes.
func MultiSizeNGrams(text string) []string {
	var all []string
	for _, size := range DefaultNGramSizes {
		all = append(all, NGrams(text, size)...)
	}
	return all
}

var sentenceRe = regexp.MustCompile(`[.!?]+\s+|\n+`)

// Tokenize splits text into sentences using simple heuristics.
// Splits on period, exclamation, question mark followed by whitespace or end.
func Tokenize(text string) []string {
	parts := sentenceRe.Split(text, -1)
	var sentences []string
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			sentences = append(sentences, p)
		}
	}
	return sentences
}

// IsImperativeStart checks if a sentence begins with a verb-like word
// by detecting words that start with a capital or lowercase letter
// and are not common articles/pronouns/conjunctions.
// This is a structural heuristic, not pattern-based.
// nonImperative is a pre-computed set of words that typically start non-imperative sentences.
// nounSuffixes suggest a word is a noun, not an imperative verb.
var nounSuffixes = []string{"tion", "ment", "ness", "ity", "ence", "ance", "ing"}

// nonImperative is a pre-computed set of words that typically start non-imperative sentences.
var nonImperative = map[string]bool{
	"the": true, "a": true, "an": true,
	"this": true, "that": true, "these": true, "those": true,
	"i": true, "you": true, "he": true, "she": true, "it": true,
	"we": true, "they": true, "my": true, "your": true, "his": true,
	"her": true, "its": true, "our": true, "their": true,
	"and": true, "or": true, "but": true, "if": true, "when": true,
	"while": true, "because": true, "since": true, "although": true,
	"however": true, "moreover": true, "furthermore": true,
	"in": true, "on": true, "at": true, "to": true, "for": true,
	"with": true, "from": true, "by": true, "of": true, "about": true,
	"there": true, "here": true, "where": true, "what": true,
	"which": true, "who": true, "how": true, "why": true,
	"not": true, "no": true, "any": true, "some": true, "all": true,
	"each": true, "every": true, "both": true, "either": true,
	"neither": true, "many": true, "much": true, "few": true,
	"most": true, "several": true, "such": true, "only": true,
	"also": true, "then": true, "so": true, "as": true,
}

func IsImperativeStart(sentence string) bool {
	words := strings.Fields(strings.TrimSpace(sentence))
	if len(words) == 0 {
		return false
	}
	first := strings.ToLower(words[0])

	if nonImperative[first] {
		return false
	}

	// Check if first word could be a verb form (heuristic: not ending in common
	// noun suffixes, and the sentence has at least 2 words suggesting a command).
	if len(words) < 2 {
		return false
	}

	// Common noun-only suffixes that suggest the first word is NOT a verb.
	for _, suffix := range nounSuffixes {
		if strings.HasSuffix(first, suffix) && len(first) > len(suffix)+2 {
			// "ing" words CAN be imperative ("bring"), so check length.
			if suffix != "ing" {
				return false
			}
		}
	}

	// Heuristic: first word is likely imperative if it doesn't match
	// known non-imperative patterns.
	// Check first character is a letter.
	if len(first) > 0 && unicode.IsLetter(rune(first[0])) {
		return true
	}

	return false
}
