package bloom

import (
	"crypto/sha256"
	"fmt"
	"testing"
)

func hashStr(s string) []byte {
	h := sha256.Sum256([]byte(s))
	return h[:]
}

func TestNewFilter(t *testing.T) {
	f := New(1000, 0.01)
	if f.Size() == 0 {
		t.Fatal("filter size must be > 0")
	}
	if f.HashCount() == 0 {
		t.Fatal("hash count must be > 0")
	}
	if len(f.Bytes()) == 0 {
		t.Fatal("bytes must not be empty")
	}
}

func TestAddAndTest(t *testing.T) {
	f := New(100, 0.01)

	items := []string{"alpha", "bravo", "charlie", "delta", "echo"}
	for _, item := range items {
		f.Add(hashStr(item))
	}

	// All inserted items must be found (no false negatives).
	for _, item := range items {
		if !f.Test(hashStr(item)) {
			t.Errorf("expected %q to be found in filter", item)
		}
	}
}

func TestNotInserted(t *testing.T) {
	f := New(100, 0.01)
	f.Add(hashStr("inserted"))

	// Items never inserted are very likely absent.
	absent := []string{"foxtrot", "golf", "hotel", "india", "juliet"}
	falsePositives := 0
	for _, item := range absent {
		if f.Test(hashStr(item)) {
			falsePositives++
		}
	}
	// With 1% FP rate and 5 tests, getting more than 2 FPs would be very unusual.
	if falsePositives > 2 {
		t.Errorf("too many false positives: %d out of %d", falsePositives, len(absent))
	}
}

func TestFalsePositiveRate(t *testing.T) {
	n := uint32(10000)
	fpRate := 0.01
	f := New(n, fpRate)

	// Insert n items.
	for i := uint32(0); i < n; i++ {
		f.Add(hashStr(fmt.Sprintf("item-%d", i)))
	}

	// Test 10000 items that were NOT inserted.
	fpCount := 0
	testCount := 10000
	for i := 0; i < testCount; i++ {
		if f.Test(hashStr(fmt.Sprintf("other-%d", i))) {
			fpCount++
		}
	}

	observedRate := float64(fpCount) / float64(testCount)
	// Allow up to 3x the expected rate (statistical tolerance).
	if observedRate > fpRate*3 {
		t.Errorf("false positive rate too high: observed %.4f, expected < %.4f", observedRate, fpRate*3)
	}
}

func TestNewFromRaw(t *testing.T) {
	f := New(100, 0.01)
	f.Add(hashStr("test-item"))

	// Round-trip through raw bytes.
	raw := f.Bytes()
	f2, err := NewFromRaw(raw, f.Size(), f.HashCount())
	if err != nil {
		t.Fatalf("NewFromRaw failed: %v", err)
	}

	if !f2.Test(hashStr("test-item")) {
		t.Error("reconstructed filter should find the inserted item")
	}
}

func TestNewFromRawSizeMismatch(t *testing.T) {
	_, err := NewFromRaw([]byte{0x00}, 128, 7)
	if err == nil {
		t.Error("expected error for size mismatch")
	}
}

func TestEdgeCases(t *testing.T) {
	// Zero items defaults to 1.
	f := New(0, 0.01)
	if f.Size() == 0 {
		t.Error("filter with 0 items should still have non-zero size")
	}

	// Invalid FP rate defaults to 0.01.
	f2 := New(100, -1)
	if f2.Size() == 0 {
		t.Error("filter with invalid FP rate should still work")
	}

	f3 := New(100, 2.0)
	if f3.Size() == 0 {
		t.Error("filter with FP rate > 1 should still work")
	}
}
