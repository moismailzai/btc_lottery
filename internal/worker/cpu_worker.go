package worker

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"
	"sync/atomic"

	"btc_lottery/internal/lookup"

	"github.com/btcsuite/btcd/btcec/v2/schnorr"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/btcutil/hdkeychain"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/btcsuite/btcd/txscript"
	"github.com/tyler-smith/go-bip39"
)

// CPUWorker generates addresses on CPU and checks against in-memory hash set.
type CPUWorker struct {
	hashSet *lookup.AddressHashSet
	cfg     Config

	addressesChecked   int64
	mnemonicsGenerated int64
	matchesFound       int64
}

// NewCPUWorker creates a new CPU-based worker.
func NewCPUWorker(hashSet *lookup.AddressHashSet, cfg Config) *CPUWorker {
	return &CPUWorker{
		hashSet: hashSet,
		cfg:     cfg,
	}
}

// Run starts the worker loop.
func (w *CPUWorker) Run(ctx context.Context) <-chan Match {
	matches := make(chan Match, 10)

	go func() {
		defer close(matches)

		for {
			select {
			case <-ctx.Done():
				return
			default:
				foundMatches, err := w.generateAndCheck()
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
func (w *CPUWorker) Stats() Stats {
	return Stats{
		AddressesChecked:   atomic.LoadInt64(&w.addressesChecked),
		MnemonicsGenerated: atomic.LoadInt64(&w.mnemonicsGenerated),
		MatchesFound:       atomic.LoadInt64(&w.matchesFound),
	}
}

// Close releases resources.
func (w *CPUWorker) Close() error {
	return nil
}

// generateAndCheck generates a mnemonic, derives addresses, and checks for matches.
func (w *CPUWorker) generateAndCheck() ([]Match, error) {
	// Generate random mnemonic
	entropy, err := bip39.NewEntropy(w.cfg.EntropyBits)
	if err != nil {
		return nil, fmt.Errorf("generating entropy: %w", err)
	}

	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		return nil, fmt.Errorf("creating mnemonic: %w", err)
	}

	// Generate seed from mnemonic
	seed := bip39.NewSeed(mnemonic, "")

	// Derive master key using hdkeychain (much faster than go-bip32)
	masterKey, err := hdkeychain.NewMaster(seed, &chaincfg.MainNetParams)
	if err != nil {
		return nil, fmt.Errorf("creating master key: %w", err)
	}

	atomic.AddInt64(&w.mnemonicsGenerated, 1)

	// Pre-derive change keys for each address type (cache hardened derivation)
	changeKeys := make(map[uint32]*hdkeychain.ExtendedKey)
	for _, purpose := range []uint32{44, 49, 84, 86} {
		changeKey, err := deriveChangeKeyHD(masterKey, purpose)
		if err != nil {
			return nil, fmt.Errorf("deriving change key for purpose %d: %w", purpose, err)
		}
		changeKeys[purpose] = changeKey
	}

	// Generate all addresses using cached change keys
	addresses := make([]addressInfo, 0, 4*w.cfg.AddressIndexes)

	for idx := uint32(0); idx < uint32(w.cfg.AddressIndexes); idx++ {
		// BIP44 - P2PKH
		addr, err := w.deriveP2PKHFromChangeHD(changeKeys[44], idx, mnemonic)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, addr)

		// BIP49 - P2SH-P2WPKH
		addr, err = w.deriveP2SHFromChangeHD(changeKeys[49], idx, mnemonic)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, addr)

		// BIP84 - P2WPKH
		addr, err = w.deriveP2WPKHFromChangeHD(changeKeys[84], idx, mnemonic)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, addr)

		// BIP86 - P2TR
		addr, err = w.deriveP2TRFromChangeHD(changeKeys[86], idx, mnemonic)
		if err != nil {
			return nil, err
		}
		addresses = append(addresses, addr)
	}

	atomic.AddInt64(&w.addressesChecked, int64(len(addresses)))

	// Check all addresses against hash set
	addrStrings := make([]string, len(addresses))
	for i, a := range addresses {
		addrStrings[i] = a.address
	}

	found := w.hashSet.ContainsBatch(addrStrings)

	var matches []Match
	for _, addr := range addresses {
		if found[addr.address] {
			atomic.AddInt64(&w.matchesFound, 1)
			matches = append(matches, Match{
				Address:    addr.address,
				PrivateKey: addr.privateKey,
				PublicKey:  addr.publicKey,
				Mnemonic:   addr.mnemonic,
				AddrType:   addr.addrType,
			})
		}
	}

	return matches, nil
}

type addressInfo struct {
	address    string
	privateKey string
	publicKey  string
	mnemonic   string
	addrType   string
}

// deriveChangeKeyHD derives the change key (m/purpose'/0'/0'/0) using hdkeychain.
// This is much faster than go-bip32 as it doesn't compute fingerprints.
func deriveChangeKeyHD(masterKey *hdkeychain.ExtendedKey, purpose uint32) (*hdkeychain.ExtendedKey, error) {
	purposeKey, err := masterKey.Derive(hdkeychain.HardenedKeyStart + purpose)
	if err != nil {
		return nil, fmt.Errorf("deriving purpose key: %w", err)
	}

	coinType, err := purposeKey.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, fmt.Errorf("deriving coin type key: %w", err)
	}

	account, err := coinType.Derive(hdkeychain.HardenedKeyStart + 0)
	if err != nil {
		return nil, fmt.Errorf("deriving account key: %w", err)
	}

	change, err := account.Derive(0)
	if err != nil {
		return nil, fmt.Errorf("deriving change key: %w", err)
	}

	return change, nil
}

func (w *CPUWorker) deriveP2PKHFromChangeHD(changeKey *hdkeychain.ExtendedKey, idx uint32, mnemonic string) (addressInfo, error) {
	childKey, err := changeKey.Derive(idx)
	if err != nil {
		return addressInfo{}, err
	}

	privKey, err := childKey.ECPrivKey()
	if err != nil {
		return addressInfo{}, err
	}

	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return addressInfo{}, err
	}

	pubKeyBytes := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKeyBytes)

	addr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return addressInfo{}, err
	}

	return addressInfo{
		address:    addr.EncodeAddress(),
		privateKey: wif.String(),
		publicKey:  hex.EncodeToString(pubKeyBytes),
		mnemonic:   mnemonic,
		addrType:   fmt.Sprintf("p2pkh/%d", idx),
	}, nil
}

func (w *CPUWorker) deriveP2SHFromChangeHD(changeKey *hdkeychain.ExtendedKey, idx uint32, mnemonic string) (addressInfo, error) {
	childKey, err := changeKey.Derive(idx)
	if err != nil {
		return addressInfo{}, err
	}

	privKey, err := childKey.ECPrivKey()
	if err != nil {
		return addressInfo{}, err
	}

	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return addressInfo{}, err
	}

	pubKeyBytes := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKeyBytes)

	witnessProgram := append([]byte{0x00, 0x14}, pubKeyHash...)
	scriptHash := btcutil.Hash160(witnessProgram)

	addr, err := btcutil.NewAddressScriptHashFromHash(scriptHash, &chaincfg.MainNetParams)
	if err != nil {
		return addressInfo{}, err
	}

	return addressInfo{
		address:    addr.EncodeAddress(),
		privateKey: wif.String(),
		publicKey:  hex.EncodeToString(pubKeyBytes),
		mnemonic:   mnemonic,
		addrType:   fmt.Sprintf("p2sh-p2wpkh/%d", idx),
	}, nil
}

func (w *CPUWorker) deriveP2WPKHFromChangeHD(changeKey *hdkeychain.ExtendedKey, idx uint32, mnemonic string) (addressInfo, error) {
	childKey, err := changeKey.Derive(idx)
	if err != nil {
		return addressInfo{}, err
	}

	privKey, err := childKey.ECPrivKey()
	if err != nil {
		return addressInfo{}, err
	}

	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return addressInfo{}, err
	}

	pubKeyBytes := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKeyBytes)

	addr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		return addressInfo{}, err
	}

	return addressInfo{
		address:    addr.EncodeAddress(),
		privateKey: wif.String(),
		publicKey:  hex.EncodeToString(pubKeyBytes),
		mnemonic:   mnemonic,
		addrType:   fmt.Sprintf("p2wpkh/%d", idx),
	}, nil
}

func (w *CPUWorker) deriveP2TRFromChangeHD(changeKey *hdkeychain.ExtendedKey, idx uint32, mnemonic string) (addressInfo, error) {
	childKey, err := changeKey.Derive(idx)
	if err != nil {
		return addressInfo{}, err
	}

	privKey, err := childKey.ECPrivKey()
	if err != nil {
		return addressInfo{}, err
	}

	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		return addressInfo{}, err
	}

	internalPubKey := privKey.PubKey()
	taprootKey := txscript.ComputeTaprootKeyNoScript(internalPubKey)

	addr, err := btcutil.NewAddressTaproot(schnorr.SerializePubKey(taprootKey), &chaincfg.MainNetParams)
	if err != nil {
		return addressInfo{}, err
	}

	return addressInfo{
		address:    addr.EncodeAddress(),
		privateKey: wif.String(),
		publicKey:  hex.EncodeToString(schnorr.SerializePubKey(internalPubKey)),
		mnemonic:   mnemonic,
		addrType:   fmt.Sprintf("p2tr/%d", idx),
	}, nil
}
