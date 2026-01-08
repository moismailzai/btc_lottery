// Package gtable generates the precomputed secp256k1 GTable for GPU point multiplication.
//
// The GTable contains 16 * 65536 = 1,048,576 precomputed points.
// Each point has X and Y coordinates (32 bytes each = 64 bytes per point).
// Total size: ~67 MB
//
// Structure:
// - 16 chunks, each containing 65536 points
// - Chunk i contains: k * 2^(16*i) * G for k in [1, 65535]
// - This allows any 256-bit scalar multiplication using only 16 point additions
package gtable

import (
	"encoding/binary"
	"fmt"
	"math/big"
	"os"
)

// Secp256k1 curve parameters
var (
	// Prime field P
	P, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F", 16)
	// Curve order N
	N, _ = new(big.Int).SetString("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)
	// Generator point G
	Gx, _ = new(big.Int).SetString("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798", 16)
	Gy, _ = new(big.Int).SetString("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8", 16)
)

// Point represents a point on the secp256k1 curve in affine coordinates
type Point struct {
	X, Y *big.Int
}

// NewPoint creates a new point
func NewPoint(x, y *big.Int) *Point {
	return &Point{X: new(big.Int).Set(x), Y: new(big.Int).Set(y)}
}

// IsInfinity returns true if this is the point at infinity
func (p *Point) IsInfinity() bool {
	return p.X == nil && p.Y == nil
}

// Infinity returns the point at infinity
func Infinity() *Point {
	return &Point{X: nil, Y: nil}
}

// G returns the generator point
func G() *Point {
	return NewPoint(Gx, Gy)
}

// Add adds two points on the curve (affine coordinates)
func Add(p1, p2 *Point) *Point {
	if p1.IsInfinity() {
		return NewPoint(p2.X, p2.Y)
	}
	if p2.IsInfinity() {
		return NewPoint(p1.X, p1.Y)
	}

	// Check if points are the same (need to double instead)
	if p1.X.Cmp(p2.X) == 0 {
		if p1.Y.Cmp(p2.Y) == 0 {
			return Double(p1)
		}
		return Infinity() // p1 = -p2
	}

	// s = (y2 - y1) / (x2 - x1)
	dy := new(big.Int).Sub(p2.Y, p1.Y)
	dx := new(big.Int).Sub(p2.X, p1.X)
	dx.ModInverse(dx, P)
	s := new(big.Int).Mul(dy, dx)
	s.Mod(s, P)

	// x3 = s^2 - x1 - x2
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, p1.X)
	x3.Sub(x3, p2.X)
	x3.Mod(x3, P)

	// y3 = s * (x1 - x3) - y1
	y3 := new(big.Int).Sub(p1.X, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, p1.Y)
	y3.Mod(y3, P)

	return &Point{X: x3, Y: y3}
}

// Double doubles a point on the curve
func Double(p *Point) *Point {
	if p.IsInfinity() || p.Y.Sign() == 0 {
		return Infinity()
	}

	// s = 3 * x^2 / (2 * y)  (a = 0 for secp256k1)
	x2 := new(big.Int).Mul(p.X, p.X)
	x2.Mod(x2, P)

	numerator := new(big.Int).Mul(x2, big.NewInt(3))
	numerator.Mod(numerator, P)

	denominator := new(big.Int).Mul(p.Y, big.NewInt(2))
	denominator.ModInverse(denominator, P)

	s := new(big.Int).Mul(numerator, denominator)
	s.Mod(s, P)

	// x3 = s^2 - 2*x
	x3 := new(big.Int).Mul(s, s)
	x3.Sub(x3, p.X)
	x3.Sub(x3, p.X)
	x3.Mod(x3, P)

	// y3 = s * (x - x3) - y
	y3 := new(big.Int).Sub(p.X, x3)
	y3.Mul(y3, s)
	y3.Sub(y3, p.Y)
	y3.Mod(y3, P)

	return &Point{X: x3, Y: y3}
}

// ToBytes converts a point to 64 bytes (32 for X, 32 for Y)
// Uses little-endian byte order to match GPU expectations
func (p *Point) ToBytes() (xBytes, yBytes [32]byte) {
	if p.IsInfinity() {
		return // Returns zero bytes for infinity
	}

	xBig := p.X.Bytes()
	yBig := p.Y.Bytes()

	// Big.Int.Bytes() returns big-endian, but we need little-endian for GPU
	// Copy in reverse order
	for i := 0; i < len(xBig) && i < 32; i++ {
		xBytes[i] = xBig[len(xBig)-1-i]
	}
	for i := 0; i < len(yBig) && i < 32; i++ {
		yBytes[i] = yBig[len(yBig)-1-i]
	}

	return
}

// GTable holds the precomputed points
type GTable struct {
	// X and Y coordinates stored separately for better GPU memory access patterns
	X []byte // 16 * 65536 * 32 bytes
	Y []byte // 16 * 65536 * 32 bytes
}

// Generate creates the GTable with precomputed points
// Progress callback receives chunk number (0-15)
func Generate(progress func(chunk int)) (*GTable, error) {
	const numChunks = 16
	const chunkSize = 65536
	const pointBytes = 32

	gt := &GTable{
		X: make([]byte, numChunks*chunkSize*pointBytes),
		Y: make([]byte, numChunks*chunkSize*pointBytes),
	}

	// N is the current point being computed
	N := G()

	for chunk := 0; chunk < numChunks; chunk++ {
		if progress != nil {
			progress(chunk)
		}

		// Store N as the first point of this chunk (represents 1 * 2^(16*chunk) * G)
		baseOffset := chunk * chunkSize * pointBytes
		xBytes, yBytes := N.ToBytes()
		copy(gt.X[baseOffset:baseOffset+pointBytes], xBytes[:])
		copy(gt.Y[baseOffset:baseOffset+pointBytes], yBytes[:])

		// Save the base point for this chunk (used for additions)
		chunkBase := NewPoint(N.X, N.Y)

		// Double N for the next entry
		N = Double(N)

		// Generate remaining points: N, N+base, N+2*base, ... (effectively 2, 3, 4, ...)
		for j := 1; j < chunkSize-1; j++ {
			offset := baseOffset + j*pointBytes
			xBytes, yBytes = N.ToBytes()
			copy(gt.X[offset:offset+pointBytes], xBytes[:])
			copy(gt.Y[offset:offset+pointBytes], yBytes[:])

			// N = N + chunkBase
			N = Add(N, chunkBase)
		}

		// At this point N should be 65536 * chunkBase = 2^16 * chunkBase = 2^(16*(chunk+1)) * G
		// This is the starting point for the next chunk
	}

	return gt, nil
}

// Save writes the GTable to two binary files
func (gt *GTable) Save(xPath, yPath string) error {
	if err := os.WriteFile(xPath, gt.X, 0644); err != nil {
		return fmt.Errorf("failed to write X table: %w", err)
	}
	if err := os.WriteFile(yPath, gt.Y, 0644); err != nil {
		return fmt.Errorf("failed to write Y table: %w", err)
	}
	return nil
}

// Load reads the GTable from two binary files
func Load(xPath, yPath string) (*GTable, error) {
	x, err := os.ReadFile(xPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read X table: %w", err)
	}
	y, err := os.ReadFile(yPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read Y table: %w", err)
	}

	const expectedSize = 16 * 65536 * 32
	if len(x) != expectedSize {
		return nil, fmt.Errorf("X table size mismatch: got %d, want %d", len(x), expectedSize)
	}
	if len(y) != expectedSize {
		return nil, fmt.Errorf("Y table size mismatch: got %d, want %d", len(y), expectedSize)
	}

	return &GTable{X: x, Y: y}, nil
}

// Verify checks that the first few points are correct
func (gt *GTable) Verify() error {
	// Verify first point is G
	var xBytes, yBytes [32]byte
	copy(xBytes[:], gt.X[0:32])
	copy(yBytes[:], gt.Y[0:32])

	// Convert back to big.Int (little-endian to big-endian)
	xBig := new(big.Int)
	yBig := new(big.Int)
	for i := 31; i >= 0; i-- {
		xBig.Lsh(xBig, 8)
		xBig.Or(xBig, big.NewInt(int64(xBytes[i])))
		yBig.Lsh(yBig, 8)
		yBig.Or(yBig, big.NewInt(int64(yBytes[i])))
	}

	if xBig.Cmp(Gx) != 0 {
		return fmt.Errorf("first point X mismatch: got %s, want %s", xBig.Text(16), Gx.Text(16))
	}
	if yBig.Cmp(Gy) != 0 {
		return fmt.Errorf("first point Y mismatch: got %s, want %s", yBig.Text(16), Gy.Text(16))
	}

	return nil
}

// PointAt returns the point at the given index
func (gt *GTable) PointAt(index int) (*Point, error) {
	const pointBytes = 32
	if index < 0 || index >= 16*65536 {
		return nil, fmt.Errorf("index out of range: %d", index)
	}

	offset := index * pointBytes

	// Convert from little-endian bytes to big.Int
	xBig := new(big.Int)
	yBig := new(big.Int)
	for i := 31; i >= 0; i-- {
		xBig.Lsh(xBig, 8)
		xBig.Or(xBig, big.NewInt(int64(gt.X[offset+i])))
		yBig.Lsh(yBig, 8)
		yBig.Or(yBig, big.NewInt(int64(gt.Y[offset+i])))
	}

	return NewPoint(xBig, yBig), nil
}

// GeneratorHash computes the hash of the first 8 bytes for verification
func (gt *GTable) GeneratorHash() uint64 {
	return binary.LittleEndian.Uint64(gt.X[0:8])
}
