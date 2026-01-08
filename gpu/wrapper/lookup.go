package wrapper

import (
	"encoding/binary"
	"fmt"
	"os"
	"sync"
	"unsafe"
)

// GPULookup provides GPU-accelerated address lookup using binary search.
type GPULookup struct {
	device    *Device
	module    *Module
	searchFn  *Function
	hashMem   *DeviceMemory
	hashCount int

	// Reusable query buffers
	queryMem  *DeviceMemory
	resultMem *DeviceMemory
	maxBatch  int

	mu sync.Mutex
}

// NewGPULookup creates a GPU-accelerated lookup from sorted hashes.
func NewGPULookup(hashes []uint64, ptxPath string) (*GPULookup, error) {
	if err := InitCUDA(); err != nil {
		return nil, fmt.Errorf("initializing CUDA: %w", err)
	}

	count, err := DeviceCount()
	if err != nil || count == 0 {
		return nil, fmt.Errorf("no CUDA devices available")
	}

	device, err := NewDevice(0)
	if err != nil {
		return nil, fmt.Errorf("creating device: %w", err)
	}

	// Load PTX
	ptx, err := os.ReadFile(ptxPath)
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("reading PTX: %w", err)
	}

	module, err := LoadModule(string(ptx))
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("loading module: %w", err)
	}

	searchFn, err := module.GetFunction("test_binary_search")
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("getting function: %w", err)
	}

	// Allocate hash memory on GPU
	hashMem, err := device.Alloc(uint64(len(hashes) * 8))
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("allocating hash memory: %w", err)
	}

	// Copy hashes to GPU
	hashBytes := make([]byte, len(hashes)*8)
	for i, h := range hashes {
		binary.LittleEndian.PutUint64(hashBytes[i*8:], h)
	}
	if err := hashMem.CopyFromHost(hashBytes); err != nil {
		hashMem.Free()
		device.Close()
		return nil, fmt.Errorf("copying hashes: %w", err)
	}

	// Pre-allocate query buffers for typical batch size
	maxBatch := 100000 // 100K addresses per batch
	queryMem, err := device.Alloc(uint64(maxBatch * 8))
	if err != nil {
		hashMem.Free()
		device.Close()
		return nil, fmt.Errorf("allocating query memory: %w", err)
	}

	resultMem, err := device.Alloc(uint64(maxBatch * 4))
	if err != nil {
		queryMem.Free()
		hashMem.Free()
		device.Close()
		return nil, fmt.Errorf("allocating result memory: %w", err)
	}

	return &GPULookup{
		device:    device,
		module:    module,
		searchFn:  searchFn,
		hashMem:   hashMem,
		hashCount: len(hashes),
		queryMem:  queryMem,
		resultMem: resultMem,
		maxBatch:  maxBatch,
	}, nil
}

// Close releases GPU resources.
func (g *GPULookup) Close() error {
	g.mu.Lock()
	defer g.mu.Unlock()

	if g.resultMem != nil {
		g.resultMem.Free()
	}
	if g.queryMem != nil {
		g.queryMem.Free()
	}
	if g.hashMem != nil {
		g.hashMem.Free()
	}
	if g.device != nil {
		g.device.Close()
	}
	return nil
}

// Lookup checks which addresses exist in the hash set.
// Returns a slice of booleans indicating which addresses were found.
func (g *GPULookup) Lookup(addressHashes []uint64) ([]bool, error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	if len(addressHashes) == 0 {
		return nil, nil
	}

	if len(addressHashes) > g.maxBatch {
		return nil, fmt.Errorf("batch size %d exceeds max %d", len(addressHashes), g.maxBatch)
	}

	// Copy queries to GPU
	queryBytes := make([]byte, len(addressHashes)*8)
	for i, h := range addressHashes {
		binary.LittleEndian.PutUint64(queryBytes[i*8:], h)
	}
	if err := g.queryMem.CopyFromHost(queryBytes); err != nil {
		return nil, fmt.Errorf("copying queries: %w", err)
	}

	// Launch kernel
	hashPtr := g.hashMem.Ptr()
	hashCountVal := int32(g.hashCount)
	queryPtr := g.queryMem.Ptr()
	queryCountVal := int32(len(addressHashes))
	resultPtr := g.resultMem.Ptr()

	params := []unsafe.Pointer{
		unsafe.Pointer(&hashPtr),
		unsafe.Pointer(&hashCountVal),
		unsafe.Pointer(&queryPtr),
		unsafe.Pointer(&queryCountVal),
		unsafe.Pointer(&resultPtr),
	}

	blockSize := uint32(256)
	gridSize := uint32((len(addressHashes) + int(blockSize) - 1) / int(blockSize))

	if err := g.searchFn.Launch(gridSize, 1, 1, blockSize, 1, 1, 0, params); err != nil {
		return nil, fmt.Errorf("launching kernel: %w", err)
	}

	if err := g.device.Synchronize(); err != nil {
		return nil, fmt.Errorf("synchronizing: %w", err)
	}

	// Copy results back
	resultBytes := make([]byte, len(addressHashes)*4)
	if err := g.resultMem.CopyToHost(resultBytes); err != nil {
		return nil, fmt.Errorf("copying results: %w", err)
	}

	// Convert to bool slice
	results := make([]bool, len(addressHashes))
	for i := range results {
		results[i] = binary.LittleEndian.Uint32(resultBytes[i*4:]) != 0
	}

	return results, nil
}

// HashCount returns the number of hashes in the lookup table.
func (g *GPULookup) HashCount() int {
	return g.hashCount
}
