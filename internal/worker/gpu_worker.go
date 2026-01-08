//go:build cuda

package worker

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"sync"
	"sync/atomic"

	"btc_lottery/gpu/gtable"
	"btc_lottery/gpu/wrapper"
	"btc_lottery/internal/lookup"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// GPUWorker generates addresses and checks against GPU-accelerated hash lookup.
// The GPU handles: EC point multiplication + Hash160 + binary search
// This offloads the EC math bottleneck to the GPU.
type GPUWorker struct {
	lottery   *wrapper.LotteryKernel
	hashSet   *lookup.AddressHashSet // For match verification
	cfg       Config

	addressesChecked   int64
	mnemonicsGenerated int64
	matchesFound       int64

	// Batch accumulator
	batchMu       sync.Mutex
	pendingKeys   []keyInfo // Key metadata for reconstructing matches
	pendingPrivs  []byte    // Raw 32-byte private keys for GPU
	batchThreshold int
}

// keyInfo stores metadata for each private key sent to GPU.
type keyInfo struct {
	mnemonic   string
	addrType   string
	idx        uint32
	compressed bool
}

// GPUWorkerConfig contains GPU-specific configuration.
type GPUWorkerConfig struct {
	Config
	PTXPath     string
	GTableXPath string
	GTableYPath string
}

// NewGPUWorker creates a new GPU-accelerated worker.
func NewGPUWorker(hashSet *lookup.AddressHashSet, cfg GPUWorkerConfig) (*GPUWorker, error) {
	// Initialize CUDA
	if err := wrapper.InitCUDA(); err != nil {
		return nil, fmt.Errorf("initializing CUDA: %w", err)
	}

	count, err := wrapper.DeviceCount()
	if err != nil || count == 0 {
		return nil, fmt.Errorf("no CUDA devices available")
	}

	device, err := wrapper.NewDevice(0)
	if err != nil {
		return nil, fmt.Errorf("creating device: %w", err)
	}

	log.Printf("GPU: %s (%.2f GB)", device.Name(), float64(device.Memory())/(1<<30))

	// Create lottery kernel
	lotteryConfig := wrapper.LotteryConfig{
		PTXPath:   cfg.PTXPath,
		BatchSize: cfg.GPUBatchSize * 80, // 80 addresses per mnemonic (4 types × 20 indexes)
	}

	lottery, err := wrapper.NewLotteryKernel(device, lotteryConfig)
	if err != nil {
		device.Close()
		return nil, fmt.Errorf("creating lottery kernel: %w", err)
	}

	// Load GTable (generate if not provided)
	if cfg.GTableXPath != "" && cfg.GTableYPath != "" {
		if err := lottery.LoadGTable(cfg.GTableXPath, cfg.GTableYPath); err != nil {
			lottery.Close()
			device.Close()
			return nil, fmt.Errorf("loading GTable: %w", err)
		}
		log.Printf("Loaded GTable from files")
	} else {
		// Generate GTable in memory
		log.Printf("Generating GTable (this may take a moment)...")
		gt, err := gtable.Generate(nil)
		if err != nil {
			lottery.Close()
			device.Close()
			return nil, fmt.Errorf("generating GTable: %w", err)
		}
		if err := lottery.LoadGTableFromBytes(gt.X, gt.Y); err != nil {
			lottery.Close()
			device.Close()
			return nil, fmt.Errorf("loading GTable to GPU: %w", err)
		}
		log.Printf("GTable loaded to GPU")
	}

	// Load hash table from address set
	hashes := hashSet.Hashes()
	if err := lottery.LoadHashTable(hashes); err != nil {
		lottery.Close()
		device.Close()
		return nil, fmt.Errorf("loading hash table: %w", err)
	}
	log.Printf("Loaded %d address hashes to GPU", len(hashes))

	batchSize := cfg.GPUBatchSize
	if batchSize == 0 {
		batchSize = 12500
	}

	return &GPUWorker{
		lottery:        lottery,
		hashSet:        hashSet,
		cfg:            cfg.Config,
		pendingKeys:    make([]keyInfo, 0, batchSize*80),
		pendingPrivs:   make([]byte, 0, batchSize*80*32),
		batchThreshold: batchSize * 80,
	}, nil
}

// Run starts the worker loop.
func (w *GPUWorker) Run(ctx context.Context) <-chan Match {
	matches := make(chan Match, 100)

	go func() {
		defer close(matches)

		for {
			select {
			case <-ctx.Done():
				// Flush remaining batch
				w.flushBatch(matches)
				return
			default:
				foundMatches, err := w.generateAndQueue()
				if err != nil {
					if w.cfg.Verbose {
						log.Printf("Error generating addresses: %v", err)
					}
					continue
				}

				for _, m := range foundMatches {
					select {
					case matches <- m:
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return matches
}

// Stats returns current statistics.
func (w *GPUWorker) Stats() Stats {
	return Stats{
		AddressesChecked:   atomic.LoadInt64(&w.addressesChecked),
		MnemonicsGenerated: atomic.LoadInt64(&w.mnemonicsGenerated),
		MatchesFound:       atomic.LoadInt64(&w.matchesFound),
	}
}

// Close releases resources.
func (w *GPUWorker) Close() error {
	if w.lottery != nil {
		return w.lottery.Close()
	}
	return nil
}

// generateAndQueue generates private keys and queues them for GPU processing.
func (w *GPUWorker) generateAndQueue() ([]Match, error) {
	// Generate random mnemonic
	entropy, err := bip39.NewEntropy(w.cfg.EntropyBits)
	if err != nil {
		return nil, fmt.Errorf("generating entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("creating mnemonic: %w", err)
	}

	seed := bip39.NewSeed(mnemonic, "")
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		return nil, fmt.Errorf("creating master key: %w", err)
	}

	atomic.AddInt64(&w.mnemonicsGenerated, 1)

	// Derive all private keys for this mnemonic
	w.batchMu.Lock()

	for idx := uint32(0); idx < uint32(w.cfg.AddressIndexes); idx++ {
		// BIP44 - P2PKH (uses compressed pubkey hash)
		privKey, err := derivePrivateKey(masterKey, 44, idx)
		if err != nil {
			w.batchMu.Unlock()
			return nil, err
		}
		w.pendingKeys = append(w.pendingKeys, keyInfo{
			mnemonic:   mnemonic,
			addrType:   fmt.Sprintf("p2pkh/%d", idx),
			idx:        idx,
			compressed: true,
		})
		w.pendingPrivs = append(w.pendingPrivs, privKey...)

		// BIP49 - P2SH-P2WPKH (uses compressed pubkey hash)
		privKey, err = derivePrivateKey(masterKey, 49, idx)
		if err != nil {
			w.batchMu.Unlock()
			return nil, err
		}
		w.pendingKeys = append(w.pendingKeys, keyInfo{
			mnemonic:   mnemonic,
			addrType:   fmt.Sprintf("p2sh-p2wpkh/%d", idx),
			idx:        idx,
			compressed: true,
		})
		w.pendingPrivs = append(w.pendingPrivs, privKey...)

		// BIP84 - P2WPKH (uses compressed pubkey hash)
		privKey, err = derivePrivateKey(masterKey, 84, idx)
		if err != nil {
			w.batchMu.Unlock()
			return nil, err
		}
		w.pendingKeys = append(w.pendingKeys, keyInfo{
			mnemonic:   mnemonic,
			addrType:   fmt.Sprintf("p2wpkh/%d", idx),
			idx:        idx,
			compressed: true,
		})
		w.pendingPrivs = append(w.pendingPrivs, privKey...)

		// BIP86 - P2TR (Taproot - uses x-only pubkey)
		privKey, err = derivePrivateKey(masterKey, 86, idx)
		if err != nil {
			w.batchMu.Unlock()
			return nil, err
		}
		w.pendingKeys = append(w.pendingKeys, keyInfo{
			mnemonic:   mnemonic,
			addrType:   fmt.Sprintf("p2tr/%d", idx),
			idx:        idx,
			compressed: true, // P2TR also uses compressed for Hash160
		})
		w.pendingPrivs = append(w.pendingPrivs, privKey...)
	}

	// Check if batch is ready
	var matches []Match
	if len(w.pendingKeys) >= w.batchThreshold {
		matches = w.processBatchLocked()
	}
	w.batchMu.Unlock()

	return matches, nil
}

// flushBatch processes any remaining keys in the batch.
func (w *GPUWorker) flushBatch(matchChan chan<- Match) {
	w.batchMu.Lock()
	defer w.batchMu.Unlock()

	if len(w.pendingKeys) > 0 {
		matches := w.processBatchLocked()
		for _, m := range matches {
			matchChan <- m
		}
	}
}

// processBatchLocked processes the current batch using GPU.
// Must be called with batchMu held.
func (w *GPUWorker) processBatchLocked() []Match {
	if len(w.pendingKeys) == 0 {
		return nil
	}

	// Process batch on GPU
	gpuMatches, err := w.lottery.ProcessBatch(w.pendingPrivs)
	if err != nil {
		log.Printf("GPU processing error: %v, falling back to CPU", err)
		return w.cpuFallbackLocked()
	}

	atomic.AddInt64(&w.addressesChecked, int64(len(w.pendingKeys)))

	// Convert GPU matches to full matches with verification
	var matches []Match
	for _, gm := range gpuMatches {
		// Find the key index based on private key match
		for i, info := range w.pendingKeys {
			if i*32 >= len(w.pendingPrivs) {
				break
			}
			// Check if this is the matching key
			keyMatch := true
			for j := 0; j < 32; j++ {
				if w.pendingPrivs[i*32+j] != gm.PrivKey[j] {
					keyMatch = false
					break
				}
			}
			if keyMatch {
				// Reconstruct full address info
				fullMatch, err := w.reconstructMatch(w.pendingPrivs[i*32:(i+1)*32], info)
				if err != nil {
					if w.cfg.Verbose {
						log.Printf("Failed to reconstruct match: %v", err)
					}
					continue
				}

				// Verify against hash set
				if w.hashSet.Contains(fullMatch.Address) {
					atomic.AddInt64(&w.matchesFound, 1)
					matches = append(matches, fullMatch)
				}
				break
			}
		}
	}

	// Clear batch
	w.pendingKeys = w.pendingKeys[:0]
	w.pendingPrivs = w.pendingPrivs[:0]

	return matches
}

// reconstructMatch reconstructs full match info from private key and metadata.
// privKeyBytes is in little-endian format (from GPU), needs conversion for btcec.
func (w *GPUWorker) reconstructMatch(privKeyBytes []byte, info keyInfo) (Match, error) {
	// Convert from GPU little-endian to btcec big-endian
	beKey := leKeyToBigEndian(privKeyBytes)
	privKey, _ := btcec.PrivKeyFromBytes(beKey)
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return Match{}, err
	}

	pubKeyBytes := wif.SerializePubKey()
	var address string

	switch info.addrType[:4] {
	case "p2pk": // P2PKH
		pubKeyHash := btcutil.Hash160(pubKeyBytes)
		addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		if err != nil {
			return Match{}, err
		}
		address = addr.EncodeAddress()

	case "p2sh": // P2SH-P2WPKH
		pubKeyHash := btcutil.Hash160(pubKeyBytes)
		witnessProgram := append([]byte{0x00, 0x14}, pubKeyHash...)
		scriptHash := btcutil.Hash160(witnessProgram)
		addr, err := btcutil.NewAddressScriptHashFromHash(scriptHash, &chaincfg.MainNetParams)
		if err != nil {
			return Match{}, err
		}
		address = addr.EncodeAddress()

	case "p2wp": // P2WPKH
		pubKeyHash := btcutil.Hash160(pubKeyBytes)
		addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
		if err != nil {
			return Match{}, err
		}
		address = addr.EncodeAddress()

	case "p2tr": // P2TR
		internalPubKey := privKey.PubKey()
		taprootKey := txscript.ComputeTaprootKeyNoScript(internalPubKey)
		addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootKey), &chaincfg.MainNetParams)
		if err != nil {
			return Match{}, err
		}
		address = addr.EncodeAddress()
		pubKeyBytes = schnorr.SerializePubKey(internalPubKey)
	}

	return Match{
		Address:    address,
		PrivateKey: wif.String(),
		PublicKey:  hex.EncodeToString(pubKeyBytes),
		Mnemonic:   info.mnemonic,
		AddrType:   info.addrType,
	}, nil
}

// cpuFallbackLocked falls back to CPU lookup if GPU fails.
func (w *GPUWorker) cpuFallbackLocked() []Match {
	atomic.AddInt64(&w.addressesChecked, int64(len(w.pendingKeys)))

	var matches []Match
	for i, info := range w.pendingKeys {
		if i*32 >= len(w.pendingPrivs) {
			break
		}
		fullMatch, err := w.reconstructMatch(w.pendingPrivs[i*32:(i+1)*32], info)
		if err != nil {
			continue
		}
		if w.hashSet.Contains(fullMatch.Address) {
			atomic.AddInt64(&w.matchesFound, 1)
			matches = append(matches, fullMatch)
		}
	}

	w.pendingKeys = w.pendingKeys[:0]
	w.pendingPrivs = w.pendingPrivs[:0]

	return matches
}

// derivePrivateKey derives a private key from master key following BIP44/49/84/86 path.
// Returns the key in little-endian format for GPU processing.
func derivePrivateKey(masterKey *bip32.Key, purpose uint32, addressIndex uint32) ([]byte, error) {
	purposeKey, err := masterKey.NewChildKey(bip32.FirstHardenedChild + purpose)
	if err != nil {
		return nil, fmt.Errorf("deriving purpose key: %w", err)
	}

	coinType, err := purposeKey.NewChildKey(bip32.FirstHardenedChild + 0) // Bitcoin
	if err != nil {
		return nil, fmt.Errorf("deriving coin type key: %w", err)
	}

	account, err := coinType.NewChildKey(bip32.FirstHardenedChild + 0) // Account 0
	if err != nil {
		return nil, fmt.Errorf("deriving account key: %w", err)
	}

	change, err := account.NewChildKey(0) // External chain
	if err != nil {
		return nil, fmt.Errorf("deriving change key: %w", err)
	}

	addressKey, err := change.NewChildKey(addressIndex)
	if err != nil {
		return nil, fmt.Errorf("deriving address key: %w", err)
	}

	// BIP32 keys are big-endian, GPU expects little-endian
	// Reverse the byte order
	key := addressKey.Key
	leKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		leKey[i] = key[31-i]
	}

	return leKey, nil
}

// leKeyToBigEndian converts a little-endian key back to big-endian for btcec.
func leKeyToBigEndian(leKey []byte) []byte {
	beKey := make([]byte, 32)
	for i := 0; i < 32; i++ {
		beKey[i] = leKey[31-i]
	}
	return beKey
}
