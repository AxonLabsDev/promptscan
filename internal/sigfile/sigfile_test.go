package sigfile

import (
	"bytes"
	"crypto/sha256"
	"os"
	"path/filepath"
	"testing"
)

func makeTestHash(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func TestWriteAndLoad(t *testing.T) {
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}
	bloomData := make([]byte, 16) // 128 bits
	bloomData[0] = 0xFF
	bloomSize := uint32(128)
	hashCount := uint32(7)
	hmacKey := []byte("test-hmac-key-for-testing-only!!")

	hashes := [][]byte{
		makeTestHash("alpha"),
		makeTestHash("bravo"),
		makeTestHash("charlie"),
	}

	sf := New(1, salt, bloomData, bloomSize, hashCount, hashes)

	// Write to buffer.
	var buf bytes.Buffer
	err := sf.Write(&buf, hmacKey)
	if err != nil {
		t.Fatalf("Write failed: %v", err)
	}

	// Load from buffer.
	reader := bytes.NewReader(buf.Bytes())
	loaded, err := Load(reader)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	// Verify header fields.
	if loaded.Header.Magic != Magic {
		t.Error("magic mismatch")
	}
	if loaded.Header.Version != 1 {
		t.Errorf("version: got %d, want 1", loaded.Header.Version)
	}
	if loaded.Header.Salt != salt {
		t.Error("salt mismatch")
	}
	if loaded.Header.BloomSize != bloomSize {
		t.Errorf("bloom size: got %d, want %d", loaded.Header.BloomSize, bloomSize)
	}
	if loaded.Header.HashCount != hashCount {
		t.Errorf("hash count: got %d, want %d", loaded.Header.HashCount, hashCount)
	}

	// Verify hash table.
	if len(loaded.HashTable) != 3 {
		t.Fatalf("hash table: got %d entries, want 3", len(loaded.HashTable))
	}
}

func TestWriteFileAndVerify(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "test.pgsig")
	hmacKey := []byte("test-hmac-key-for-testing-only!!")
	salt := [16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16}

	hashes := [][]byte{makeTestHash("test-pattern")}
	bloomData := make([]byte, 8) // 64 bits
	sf := New(1, salt, bloomData, 64, 5, hashes)

	err := sf.WriteFile(path, hmacKey)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Verify HMAC.
	err = Verify(path, hmacKey)
	if err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	// Tamper with file and verify fails.
	data, _ := os.ReadFile(path)
	data[len(data)-5] ^= 0xFF // flip some HMAC bits
	os.WriteFile(path, data, 0644)

	err = Verify(path, hmacKey)
	if err == nil {
		t.Error("Verify should fail after tampering")
	}
}

func TestLookupHash(t *testing.T) {
	salt := [16]byte{}
	hashes := [][]byte{
		makeTestHash("alpha"),
		makeTestHash("bravo"),
		makeTestHash("charlie"),
		makeTestHash("delta"),
		makeTestHash("echo"),
	}
	sf := New(1, salt, make([]byte, 8), 64, 5, hashes)

	// Existing hashes.
	for _, name := range []string{"alpha", "bravo", "charlie", "delta", "echo"} {
		if !sf.LookupHash(makeTestHash(name)) {
			t.Errorf("expected to find hash for %q", name)
		}
	}

	// Non-existing hash.
	if sf.LookupHash(makeTestHash("foxtrot")) {
		t.Error("did not expect to find hash for 'foxtrot'")
	}
}

func TestBadMagic(t *testing.T) {
	data := []byte("NOT_PSIG_AT_ALL_GARBAGE_DATA_HERE")
	reader := bytes.NewReader(data)
	_, err := Load(reader)
	if err == nil {
		t.Error("expected error for invalid magic bytes")
	}
}

func TestVerifyTooSmall(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "tiny.pgsig")
	os.WriteFile(path, []byte("small"), 0644)
	err := Verify(path, []byte("key"))
	if err == nil {
		t.Error("expected error for file too small")
	}
}
