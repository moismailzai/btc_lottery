// Package wrapper provides GPU-accelerated BTC lottery operations.
package wrapper

import (
	"encoding/binary"
	"fmt"
	"os"
	"unsafe"
)

// LotteryKernel manages the GPU kernel for BTC address matching.
type LotteryKernel struct {
	device   *Device
	module   *Module
	kernel   *Function
	testKern *Function

	// GTable on GPU
	gTableX *DeviceMemory
	gTableY *DeviceMemory

	// Hash lookup table on GPU
	hashTable *DeviceMemory
	hashCount int

	// Batch buffers
	privKeys    *DeviceMemory
	matchFlags  *DeviceMemory
	matchPrivs  *DeviceMemory
	matchHashes *DeviceMemory
	batchSize   int

	// Host-side buffers for results
	flagsBuf  []int32
	privsBuf  []byte
	hashesBuf []byte
}

// LotteryConfig configures the lottery kernel.
type LotteryConfig struct {
	PTXPath    string // Path to btc_lottery.ptx
	GTableXPath string // Path to GTable X coordinates
	GTableYPath string // Path to GTable Y coordinates
	BatchSize  int    // Number of keys per batch (default: 65536)
}

// NewLotteryKernel creates a new GPU lottery kernel.
func NewLotteryKernel(device *Device, config LotteryConfig) (*LotteryKernel, error) {
	if config.BatchSize == 0 {
		config.BatchSize = 65536 // Default batch size
	}

	// Ensure context is current
	if err := device.SetCurrent(); err != nil {
		return nil, fmt.Errorf("failed to set context: %w", err)
	}

	// Load PTX
	ptx, err := os.ReadFile(config.PTXPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read PTX: %w", err)
	}

	module, err := LoadModule(string(ptx))
	if err != nil {
		return nil, fmt.Errorf("failed to load module: %w", err)
	}

	// Get kernel function
	kernel, err := module.GetFunction("btc_lottery_kernel")
	if err != nil {
		return nil, fmt.Errorf("failed to get kernel: %w", err)
	}

	// Get test kernel (optional)
	testKern, _ := module.GetFunction("test_gtable_kernel")

	lk := &LotteryKernel{
		device:    device,
		module:    module,
		kernel:    kernel,
		testKern:  testKern,
		batchSize: config.BatchSize,
	}

	// Load GTable if paths provided
	if config.GTableXPath != "" && config.GTableYPath != "" {
		if err := lk.LoadGTable(config.GTableXPath, config.GTableYPath); err != nil {
			return nil, fmt.Errorf("failed to load GTable: %w", err)
		}
	}

	// Allocate batch buffers
	if err := lk.allocateBatchBuffers(); err != nil {
		return nil, fmt.Errorf("failed to allocate buffers: %w", err)
	}

	return lk, nil
}

// LoadGTable loads the precomputed GTable to GPU memory.
func (lk *LotteryKernel) LoadGTable(xPath, yPath string) error {
	const expectedSize = 16 * 65536 * 32 // ~33.5 MB per coordinate

	xData, err := os.ReadFile(xPath)
	if err != nil {
		return fmt.Errorf("failed to read GTable X: %w", err)
	}
	if len(xData) != expectedSize {
		return fmt.Errorf("GTable X size mismatch: got %d, want %d", len(xData), expectedSize)
	}

	yData, err := os.ReadFile(yPath)
	if err != nil {
		return fmt.Errorf("failed to read GTable Y: %w", err)
	}
	if len(yData) != expectedSize {
		return fmt.Errorf("GTable Y size mismatch: got %d, want %d", len(yData), expectedSize)
	}

	// Allocate GPU memory
	lk.gTableX, err = lk.device.Alloc(uint64(expectedSize))
	if err != nil {
		return fmt.Errorf("failed to alloc GTable X: %w", err)
	}

	lk.gTableY, err = lk.device.Alloc(uint64(expectedSize))
	if err != nil {
		lk.gTableX.Free()
		return fmt.Errorf("failed to alloc GTable Y: %w", err)
	}

	// Copy to GPU
	if err := lk.gTableX.CopyFromHost(xData); err != nil {
		return fmt.Errorf("failed to copy GTable X: %w", err)
	}
	if err := lk.gTableY.CopyFromHost(yData); err != nil {
		return fmt.Errorf("failed to copy GTable Y: %w", err)
	}

	return nil
}

// LoadGTableFromBytes loads GTable from byte slices.
func (lk *LotteryKernel) LoadGTableFromBytes(xData, yData []byte) error {
	const expectedSize = 16 * 65536 * 32

	if len(xData) != expectedSize || len(yData) != expectedSize {
		return fmt.Errorf("GTable size mismatch")
	}

	// Ensure context is current (may have been lost after time-consuming operations)
	if err := lk.device.SetCurrent(); err != nil {
		return fmt.Errorf("failed to set context: %w", err)
	}

	var err error
	lk.gTableX, err = lk.device.Alloc(uint64(expectedSize))
	if err != nil {
		return err
	}

	lk.gTableY, err = lk.device.Alloc(uint64(expectedSize))
	if err != nil {
		lk.gTableX.Free()
		return err
	}

	if err := lk.gTableX.CopyFromHost(xData); err != nil {
		return err
	}
	if err := lk.gTableY.CopyFromHost(yData); err != nil {
		return err
	}

	return nil
}

// LoadHashTable loads the sorted hash prefixes to GPU.
// hashes should be sorted uint64 values (first 8 bytes of each Hash160).
func (lk *LotteryKernel) LoadHashTable(hashes []uint64) error {
	// Ensure context is current
	if err := lk.device.SetCurrent(); err != nil {
		return fmt.Errorf("failed to set context: %w", err)
	}

	lk.hashCount = len(hashes)

	// Convert to bytes
	data := make([]byte, len(hashes)*8)
	for i, h := range hashes {
		binary.LittleEndian.PutUint64(data[i*8:], h)
	}

	var err error
	lk.hashTable, err = lk.device.Alloc(uint64(len(data)))
	if err != nil {
		return fmt.Errorf("failed to alloc hash table: %w", err)
	}

	if err := lk.hashTable.CopyFromHost(data); err != nil {
		return fmt.Errorf("failed to copy hash table: %w", err)
	}

	return nil
}

// allocateBatchBuffers allocates GPU memory for batch processing.
func (lk *LotteryKernel) allocateBatchBuffers() error {
	var err error

	// Private keys input: batchSize * 32 bytes
	lk.privKeys, err = lk.device.Alloc(uint64(lk.batchSize * 32))
	if err != nil {
		return fmt.Errorf("failed to alloc privKeys: %w", err)
	}

	// Match flags output: batchSize * 4 bytes (int32)
	lk.matchFlags, err = lk.device.Alloc(uint64(lk.batchSize * 4))
	if err != nil {
		return fmt.Errorf("failed to alloc matchFlags: %w", err)
	}

	// Match private keys output: batchSize * 32 bytes
	lk.matchPrivs, err = lk.device.Alloc(uint64(lk.batchSize * 32))
	if err != nil {
		return fmt.Errorf("failed to alloc matchPrivs: %w", err)
	}

	// Match hashes output: batchSize * 20 bytes
	lk.matchHashes, err = lk.device.Alloc(uint64(lk.batchSize * 20))
	if err != nil {
		return fmt.Errorf("failed to alloc matchHashes: %w", err)
	}

	// Host-side result buffers
	lk.flagsBuf = make([]int32, lk.batchSize)
	lk.privsBuf = make([]byte, lk.batchSize*32)
	lk.hashesBuf = make([]byte, lk.batchSize*20)

	return nil
}

// Match represents a found match.
type Match struct {
	PrivKey   []byte // 32-byte private key
	Hash160   []byte // 20-byte hash
	MatchType int    // 1 = compressed, 2 = uncompressed
}

// ProcessBatch processes a batch of private keys and returns any matches.
// privKeys should be a flat byte slice of 32-byte private keys.
func (lk *LotteryKernel) ProcessBatch(privKeys []byte) ([]Match, error) {
	numKeys := len(privKeys) / 32
	if numKeys == 0 {
		return nil, nil
	}
	if numKeys > lk.batchSize {
		return nil, fmt.Errorf("batch size %d exceeds max %d", numKeys, lk.batchSize)
	}

	// Ensure context is current
	if err := lk.device.SetCurrent(); err != nil {
		return nil, fmt.Errorf("failed to set context: %w", err)
	}

	// Copy private keys to GPU
	if err := lk.privKeys.CopyFromHost(privKeys); err != nil {
		return nil, fmt.Errorf("failed to copy privKeys: %w", err)
	}

	// Calculate grid dimensions
	blockSize := uint32(256)
	gridSize := uint32((numKeys + int(blockSize) - 1) / int(blockSize))

	// Prepare kernel parameters
	privKeysPtr := lk.privKeys.Ptr()
	numKeysVal := int32(numKeys)
	gTableXPtr := lk.gTableX.Ptr()
	gTableYPtr := lk.gTableY.Ptr()
	hashTablePtr := lk.hashTable.Ptr()
	hashCountVal := int32(lk.hashCount)
	matchFlagsPtr := lk.matchFlags.Ptr()
	matchPrivsPtr := lk.matchPrivs.Ptr()
	matchHashesPtr := lk.matchHashes.Ptr()

	params := []unsafe.Pointer{
		unsafe.Pointer(&privKeysPtr),
		unsafe.Pointer(&numKeysVal),
		unsafe.Pointer(&gTableXPtr),
		unsafe.Pointer(&gTableYPtr),
		unsafe.Pointer(&hashTablePtr),
		unsafe.Pointer(&hashCountVal),
		unsafe.Pointer(&matchFlagsPtr),
		unsafe.Pointer(&matchPrivsPtr),
		unsafe.Pointer(&matchHashesPtr),
	}

	// Launch kernel
	if err := lk.kernel.Launch(gridSize, 1, 1, blockSize, 1, 1, 0, params); err != nil {
		return nil, fmt.Errorf("kernel launch failed: %w", err)
	}

	// Wait for completion
	if err := lk.device.Synchronize(); err != nil {
		return nil, fmt.Errorf("synchronize failed: %w", err)
	}

	// Copy results back
	flagsBytes := make([]byte, numKeys*4)
	if err := lk.matchFlags.CopyToHost(flagsBytes); err != nil {
		return nil, fmt.Errorf("failed to copy flags: %w", err)
	}

	// Check for matches
	var matches []Match
	for i := 0; i < numKeys; i++ {
		flag := int32(binary.LittleEndian.Uint32(flagsBytes[i*4:]))
		if flag > 0 {
			// Copy match data
			privBuf := make([]byte, 32)
			hashBuf := make([]byte, 20)

			// Read from GPU (need to implement offset reads or read full buffer)
			if err := lk.matchPrivs.CopyToHost(lk.privsBuf); err != nil {
				return nil, err
			}
			if err := lk.matchHashes.CopyToHost(lk.hashesBuf); err != nil {
				return nil, err
			}

			copy(privBuf, lk.privsBuf[i*32:(i+1)*32])
			copy(hashBuf, lk.hashesBuf[i*20:(i+1)*20])

			matches = append(matches, Match{
				PrivKey:   privBuf,
				Hash160:   hashBuf,
				MatchType: int(flag),
			})
		}
	}

	return matches, nil
}

// BatchSize returns the configured batch size.
func (lk *LotteryKernel) BatchSize() int {
	return lk.batchSize
}

// Close releases all GPU resources.
func (lk *LotteryKernel) Close() error {
	if lk.gTableX != nil {
		lk.gTableX.Free()
	}
	if lk.gTableY != nil {
		lk.gTableY.Free()
	}
	if lk.hashTable != nil {
		lk.hashTable.Free()
	}
	if lk.privKeys != nil {
		lk.privKeys.Free()
	}
	if lk.matchFlags != nil {
		lk.matchFlags.Free()
	}
	if lk.matchPrivs != nil {
		lk.matchPrivs.Free()
	}
	if lk.matchHashes != nil {
		lk.matchHashes.Free()
	}
	return nil
}
