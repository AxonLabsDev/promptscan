// Package bloom implements a space-efficient probabilistic filter for
// rapid pre-screening of content against known detection signatures.
package bloom

import (
	"encoding/binary"
	"errors"
	"math"
)

// Filter is a probabilistic data structure that tests set membership.
// False positives are possible; false negatives are not.
type Filter struct {
	bits    []byte
	size    uint32 // number of bits
	hashNum uint32 // number of hash functions
}

// New creates a Filter sized for expectedItems with the given false-positive rate.
func New(expectedItems uint32, fpRate float64) *Filter {
	if expectedItems == 0 {
		expectedItems = 1
	}
	if fpRate <= 0 || fpRate >= 1 {
		fpRate = 0.01
	}

	// Optimal size: m = -n*ln(p) / (ln2)^2
	m := uint32(math.Ceil(-float64(expectedItems) * math.Log(fpRate) / (math.Ln2 * math.Ln2)))
	// Round up to byte boundary
	m = ((m + 7) / 8) * 8

	// Optimal hash count: k = (m/n) * ln2
	k := uint32(math.Ceil(float64(m) / float64(expectedItems) * math.Ln2))
	if k < 1 {
		k = 1
	}

	return &Filter{
		bits:    make([]byte, m/8),
		size:    m,
		hashNum: k,
	}
}

// NewFromRaw reconstructs a Filter from serialized bytes, size and hash count.
func NewFromRaw(data []byte, size uint32, hashNum uint32) (*Filter, error) {
	expectedBytes := (size + 7) / 8
	if uint32(len(data)) != expectedBytes {
		return nil, errors.New("bloom: data size mismatch")
	}
	bits := make([]byte, len(data))
	copy(bits, data)
	return &Filter{
		bits:    bits,
		size:    size,
		hashNum: hashNum,
	}, nil
}

// Add inserts a pre-hashed item (SHA-256 digest) into the filter.
func (f *Filter) Add(hash []byte) {
	for i := uint32(0); i < f.hashNum; i++ {
		idx := f.nthHash(hash, i)
		f.bits[idx/8] |= 1 << (idx % 8)
	}
}

// Test checks if a pre-hashed item might be in the filter.
// Returns true if possibly present, false if definitely absent.
func (f *Filter) Test(hash []byte) bool {
	for i := uint32(0); i < f.hashNum; i++ {
		idx := f.nthHash(hash, i)
		if f.bits[idx/8]&(1<<(idx%8)) == 0 {
			return false
		}
	}
	return true
}

// nthHash derives the nth hash position using enhanced double hashing
// from the first 16 bytes of the SHA-256 digest.
func (f *Filter) nthHash(hash []byte, n uint32) uint32 {
	if len(hash) < 16 {
		return 0
	}
	h1 := binary.BigEndian.Uint64(hash[0:8])
	h2 := binary.BigEndian.Uint64(hash[8:16])
	combined := h1 + uint64(n)*h2 + uint64(n)*uint64(n)
	return uint32(combined % uint64(f.size))
}

// Bytes returns the raw bit array for serialization.
func (f *Filter) Bytes() []byte {
	out := make([]byte, len(f.bits))
	copy(out, f.bits)
	return out
}

// Size returns the number of bits in the filter.
func (f *Filter) Size() uint32 {
	return f.size
}

// HashCount returns the number of hash functions used.
func (f *Filter) HashCount() uint32 {
	return f.hashNum
}
