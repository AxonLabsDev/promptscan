package hasher

import (
	"encoding/hex"
	"testing"
)

func TestNormalize(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"lowercase", "HELLO WORLD", "hello world"},
		{"collapse whitespace", "hello   world", "hello world"},
		{"strip punctuation", "hello, world!", "hello world"},
		{"trim", "  hello  ", "hello"},
		{"tabs and newlines", "hello\t\nworld", "hello world"},
		{"mixed", "  HELLO,  World!  ", "hello world"},
		{"unicode NFKC", "\uff28\uff25\uff2c\uff2c\uff2f", "hello"},
		{"empty", "", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := Normalize(tc.input)
			if got != tc.expected {
				t.Errorf("Normalize(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestHashSHA256(t *testing.T) {
	// SHA-256 of empty string is well-known.
	h := HashSHA256([]byte(""))
	got := hex.EncodeToString(h)
	want := "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
	if got != want {
		t.Errorf("SHA256('') = %s, want %s", got, want)
	}

	// Non-empty produces 32 bytes.
	h2 := HashSHA256([]byte("test"))
	if len(h2) != 32 {
		t.Errorf("expected 32 bytes, got %d", len(h2))
	}
}

func TestHashNormalized(t *testing.T) {
	// Same logical content, different formatting, should produce same hash.
	h1 := HashNormalized("Hello World")
	h2 := HashNormalized("hello   world")
	h3 := HashNormalized("  HELLO, WORLD!  ")

	hex1 := hex.EncodeToString(h1)
	hex2 := hex.EncodeToString(h2)
	hex3 := hex.EncodeToString(h3)

	if hex1 != hex2 {
		t.Errorf("expected same hash for 'Hello World' and 'hello   world'")
	}
	if hex1 != hex3 {
		t.Errorf("expected same hash for 'Hello World' and '  HELLO, WORLD!  '")
	}
}

func TestSaltedHash(t *testing.T) {
	salt := []byte("test-salt-16byte")
	h1 := SaltedHash("hello world", salt)
	h2 := SaltedHash("hello world", salt)

	if hex.EncodeToString(h1) != hex.EncodeToString(h2) {
		t.Error("same input and salt should produce same hash")
	}

	// Different salt produces different hash.
	h3 := SaltedHash("hello world", []byte("other-salt-16byt"))
	if hex.EncodeToString(h1) == hex.EncodeToString(h3) {
		t.Error("different salts should produce different hashes")
	}
}

func TestNGrams(t *testing.T) {
	text := "one two three four five"
	g3 := NGrams(text, 3)
	if len(g3) != 3 {
		t.Errorf("expected 3 trigrams, got %d", len(g3))
	}
	if g3[0] != "one two three" {
		t.Errorf("first trigram = %q, want 'one two three'", g3[0])
	}

	g5 := NGrams(text, 5)
	if len(g5) != 1 {
		t.Errorf("expected 1 five-gram, got %d", len(g5))
	}

	// Text shorter than n-gram size returns nil.
	g6 := NGrams("one two", 3)
	if g6 != nil {
		t.Errorf("expected nil for text shorter than n-gram size, got %v", g6)
	}
}

func TestMultiSizeNGrams(t *testing.T) {
	text := "one two three four five six"
	grams := MultiSizeNGrams(text)
	// 6 words: 4 trigrams + 3 four-grams + 2 five-grams = 9
	if len(grams) != 9 {
		t.Errorf("expected 9 multi-size n-grams, got %d", len(grams))
	}
}

func TestTokenize(t *testing.T) {
	text := "First sentence. Second sentence! Third? Fourth."
	sentences := Tokenize(text)
	if len(sentences) != 4 {
		t.Errorf("expected 4 sentences, got %d: %v", len(sentences), sentences)
	}
}

func TestIsImperativeStart(t *testing.T) {
	tests := []struct {
		sentence string
		expected bool
	}{
		{"Run the command now", true},
		{"Execute this task", true},
		{"The file is here", false},
		{"I want to go", false},
		{"", false},
		{"word", false}, // single word, not imperative (need >= 2 words)
		{"Delete everything", true},
		{"However the result", false},
	}

	for _, tc := range tests {
		got := IsImperativeStart(tc.sentence)
		if got != tc.expected {
			t.Errorf("IsImperativeStart(%q) = %v, want %v", tc.sentence, got, tc.expected)
		}
	}
}
