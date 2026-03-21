package decoder

import (
	"encoding/base64"
	"testing"
)

func TestRemoveZeroWidth(t *testing.T) {
	// Insert zero-width characters between letters.
	input := "he\u200Bll\u200Co\u200D wo\uFEFFrld"
	r := Decode(input, false)
	if !r.HasZeroWidthChars {
		t.Error("expected HasZeroWidthChars to be true")
	}
	want := "hello world"
	if r.Content != want {
		t.Errorf("after removing ZWC: got %q, want %q", r.Content, want)
	}
}

func TestExpandUnicodeEscapes(t *testing.T) {
	input := `\u0048\u0065\u006C\u006C\u006F`
	r := Decode(input, false)
	if !r.HasUnicodeEscapes {
		t.Error("expected HasUnicodeEscapes to be true")
	}
	if r.Content != "Hello" {
		t.Errorf("unicode expansion: got %q, want %q", r.Content, "Hello")
	}
}

func TestHTMLEntities(t *testing.T) {
	input := "&lt;script&gt;alert(1)&lt;/script&gt;"
	r := Decode(input, false)
	if !r.HasHTMLEntities {
		t.Error("expected HasHTMLEntities to be true for non-HTML file")
	}
	want := "<script>alert(1)</script>"
	if r.Content != want {
		t.Errorf("HTML decode: got %q, want %q", r.Content, want)
	}

	// HTML files should NOT decode entities.
	r2 := Decode(input, true)
	if r2.HasHTMLEntities {
		t.Error("HTML entities should not be decoded for HTML files")
	}
	if r2.Content != input {
		t.Errorf("HTML file should keep entities: got %q, want %q", r2.Content, input)
	}
}

func TestBase64Decoding(t *testing.T) {
	// Encode a readable string as base64.
	payload := "this is a test payload for decoding"
	encoded := base64.StdEncoding.EncodeToString([]byte(payload))
	input := "before " + encoded + " after"

	r := Decode(input, false)
	if !r.HasBase64 {
		t.Error("expected HasBase64 to be true")
	}
	if len(r.Base64Decoded) == 0 {
		t.Fatal("expected at least one decoded base64 segment")
	}
	if r.Base64Decoded[0] != payload {
		t.Errorf("decoded payload: got %q, want %q", r.Base64Decoded[0], payload)
	}
}

func TestBase64IgnoresBinary(t *testing.T) {
	// Binary data that happens to be valid base64 should be ignored
	// because it's not printable text.
	binaryData := make([]byte, 30)
	for i := range binaryData {
		binaryData[i] = byte(i)
	}
	encoded := base64.StdEncoding.EncodeToString(binaryData)
	input := "some text " + encoded + " more text"

	r := Decode(input, false)
	// Binary content should not be "decoded" as it's not printable.
	if r.HasBase64 {
		t.Error("binary base64 should not count as decoded text")
	}
}

func TestObfuscationScore(t *testing.T) {
	// Clean text should have zero obfuscation.
	r := Decode("just plain text here nothing special", false)
	if r.ObfuscationScore != 0.0 {
		t.Errorf("clean text obfuscation score: got %f, want 0.0", r.ObfuscationScore)
	}

	// Text with zero-width chars should have score > 0.
	r2 := Decode("te\u200Bxt", false)
	if r2.ObfuscationScore <= 0.0 {
		t.Error("text with ZWC should have positive obfuscation score")
	}
}

func TestCleanTextPassthrough(t *testing.T) {
	input := "This is a normal markdown file with no suspicious content."
	r := Decode(input, false)
	if r.HasBase64 || r.HasUnicodeEscapes || r.HasZeroWidthChars || r.HasHTMLEntities {
		t.Error("clean text should have no detection flags")
	}
	if r.Content != input {
		t.Errorf("clean text should pass through unchanged: got %q", r.Content)
	}
}
