// Package sigfile handles reading, writing, and verifying the binary
// signature database format (.pgsig) used for detection matching.
package sigfile

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"sort"
)

// Magic bytes identifying the file format.
var Magic = [4]byte{'P', 'S', 'I', 'G'}

const (
	// HeaderSize is the fixed size of the file header.
	HeaderSize = 4 + 2 + 16 + 4 + 4 + 4 // magic(4) + version(2) + salt(16) + bloom_size(4) + hash_count(4) + hmac_offset(4)
	// HashSize is the size of a single SHA-256 hash entry.
	HashSize = 32
	// HMACSize is the size of the HMAC-SHA256 tag.
	HMACSize = 32
)

// Header contains the metadata at the start of a .pgsig file.
type Header struct {
	Magic      [4]byte
	Version    uint16
	Salt       [16]byte
	BloomSize  uint32
	HashCount  uint32
	HMACOffset uint32
}

// SigFile represents a loaded signature database.
type SigFile struct {
	Header     Header
	BloomData  []byte
	HashTable  [][]byte // sorted SHA-256 hashes
	HMACKey    []byte   // derived from salt for verification
}

// New creates a new SigFile with the given parameters.
func New(version uint16, salt [16]byte, bloomData []byte, bloomSize uint32, hashCount uint32, hashes [][]byte) *SigFile {
	// Sort hashes for binary search.
	sort.Slice(hashes, func(i, j int) bool {
		return bytes.Compare(hashes[i], hashes[j]) < 0
	})

	return &SigFile{
		Header: Header{
			Magic:     Magic,
			Version:   version,
			Salt:      salt,
			BloomSize: bloomSize,
			HashCount: hashCount,
		},
		BloomData: bloomData,
		HashTable: hashes,
	}
}

// Write serializes the SigFile to a writer, computing and appending the HMAC.
func (sf *SigFile) Write(w io.Writer, hmacKey []byte) error {
	var buf bytes.Buffer

	// Write header (HMAC offset will be patched).
	if err := binary.Write(&buf, binary.BigEndian, sf.Header.Magic); err != nil {
		return fmt.Errorf("write magic: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, sf.Header.Version); err != nil {
		return fmt.Errorf("write version: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, sf.Header.Salt); err != nil {
		return fmt.Errorf("write salt: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, sf.Header.BloomSize); err != nil {
		return fmt.Errorf("write bloom size: %w", err)
	}
	if err := binary.Write(&buf, binary.BigEndian, sf.Header.HashCount); err != nil {
		return fmt.Errorf("write hash count: %w", err)
	}

	// Calculate HMAC offset: header + bloom data + hash table.
	bloomBytes := (sf.Header.BloomSize + 7) / 8
	hashTableSize := uint32(len(sf.HashTable)) * HashSize
	hmacOffset := uint32(HeaderSize) + bloomBytes + hashTableSize

	if err := binary.Write(&buf, binary.BigEndian, hmacOffset); err != nil {
		return fmt.Errorf("write hmac offset: %w", err)
	}

	// Write bloom filter data.
	if _, err := buf.Write(sf.BloomData); err != nil {
		return fmt.Errorf("write bloom data: %w", err)
	}

	// Pad bloom data to expected size.
	padding := int(bloomBytes) - len(sf.BloomData)
	if padding > 0 {
		if _, err := buf.Write(make([]byte, padding)); err != nil {
			return fmt.Errorf("write bloom padding: %w", err)
		}
	}

	// Write sorted hash table.
	for _, h := range sf.HashTable {
		if len(h) != HashSize {
			return fmt.Errorf("hash entry must be %d bytes, got %d", HashSize, len(h))
		}
		if _, err := buf.Write(h); err != nil {
			return fmt.Errorf("write hash entry: %w", err)
		}
	}

	// Compute HMAC-SHA256 over everything.
	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(buf.Bytes())
	tag := mac.Sum(nil)

	// Append HMAC.
	if _, err := buf.Write(tag); err != nil {
		return fmt.Errorf("write hmac: %w", err)
	}

	_, err := w.Write(buf.Bytes())
	return err
}

// WriteFile writes the SigFile to a filesystem path.
func (sf *SigFile) WriteFile(path string, hmacKey []byte) error {
	f, err := os.Create(path)
	if err != nil {
		return err
	}
	defer f.Close()
	return sf.Write(f, hmacKey)
}

// Load reads a .pgsig file from a reader without verifying HMAC.
func Load(r io.ReadSeeker) (*SigFile, error) {
	sf := &SigFile{}

	// Read header.
	if err := binary.Read(r, binary.BigEndian, &sf.Header.Magic); err != nil {
		return nil, fmt.Errorf("read magic: %w", err)
	}
	if sf.Header.Magic != Magic {
		return nil, errors.New("invalid signature file: bad magic bytes")
	}
	if err := binary.Read(r, binary.BigEndian, &sf.Header.Version); err != nil {
		return nil, fmt.Errorf("read version: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &sf.Header.Salt); err != nil {
		return nil, fmt.Errorf("read salt: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &sf.Header.BloomSize); err != nil {
		return nil, fmt.Errorf("read bloom size: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &sf.Header.HashCount); err != nil {
		return nil, fmt.Errorf("read hash count: %w", err)
	}
	if err := binary.Read(r, binary.BigEndian, &sf.Header.HMACOffset); err != nil {
		return nil, fmt.Errorf("read hmac offset: %w", err)
	}

	// Read bloom data.
	bloomBytes := (sf.Header.BloomSize + 7) / 8
	sf.BloomData = make([]byte, bloomBytes)
	if _, err := io.ReadFull(r, sf.BloomData); err != nil {
		return nil, fmt.Errorf("read bloom data: %w", err)
	}

	// Calculate hash table size.
	hashTableStart := uint32(HeaderSize) + bloomBytes
	if sf.Header.HMACOffset < hashTableStart {
		return nil, errors.New("invalid hmac offset")
	}
	hashTableBytes := sf.Header.HMACOffset - hashTableStart
	if hashTableBytes%HashSize != 0 {
		return nil, fmt.Errorf("hash table size %d not divisible by %d", hashTableBytes, HashSize)
	}

	// Read hash table.
	numHashes := hashTableBytes / HashSize
	sf.HashTable = make([][]byte, numHashes)
	for i := uint32(0); i < numHashes; i++ {
		h := make([]byte, HashSize)
		if _, err := io.ReadFull(r, h); err != nil {
			return nil, fmt.Errorf("read hash %d: %w", i, err)
		}
		sf.HashTable[i] = h
	}

	return sf, nil
}

// LoadFile reads a .pgsig file from a filesystem path.
func LoadFile(path string) (*SigFile, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return Load(f)
}

// Verify checks the HMAC integrity of a .pgsig file.
func Verify(path string, hmacKey []byte) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}

	if len(data) < HeaderSize+HMACSize {
		return errors.New("file too small to be a valid signature file")
	}

	// Check magic.
	if !bytes.Equal(data[:4], Magic[:]) {
		return errors.New("invalid magic bytes")
	}

	// Read HMAC offset from header.
	hmacOffset := binary.BigEndian.Uint32(data[4+2+16+4+4 : 4+2+16+4+4+4])
	if int(hmacOffset)+HMACSize != len(data) {
		return fmt.Errorf("hmac offset %d + %d != file size %d", hmacOffset, HMACSize, len(data))
	}

	// Verify HMAC.
	payload := data[:hmacOffset]
	expectedMAC := data[hmacOffset:]

	mac := hmac.New(sha256.New, hmacKey)
	mac.Write(payload)
	computedMAC := mac.Sum(nil)

	if !hmac.Equal(computedMAC, expectedMAC) {
		return errors.New("HMAC verification failed: signature file may be corrupted or tampered with")
	}

	return nil
}

// LookupHash performs binary search on the sorted hash table.
func (sf *SigFile) LookupHash(hash []byte) bool {
	lo, hi := 0, len(sf.HashTable)-1
	for lo <= hi {
		mid := lo + (hi-lo)/2
		cmp := bytes.Compare(sf.HashTable[mid], hash)
		switch {
		case cmp == 0:
			return true
		case cmp < 0:
			lo = mid + 1
		default:
			hi = mid - 1
		}
	}
	return false
}
