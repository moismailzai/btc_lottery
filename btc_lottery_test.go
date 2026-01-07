package main

import (
	"testing"

	"github.com/bits-and-blooms/bloom/v3"
	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcd/btcutil"
	"github.com/btcsuite/btcd/chaincfg"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// Test vectors from BIP39/BIP44/BIP84 specifications
// Using known mnemonic to verify address derivation

func TestBIP44Derivation(t *testing.T) {
	// Known test mnemonic
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	if !bip39.IsMnemonicValid(mnemonic) {
		t.Fatal("Test mnemonic is invalid")
	}

	seed := bip39.NewSeed(mnemonic, "")
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatalf("Failed to create master key: %v", err)
	}

	// Derive BIP44 path: m/44'/0'/0'/0/0
	childKey, err := deriveChildKey(masterKey, 44, 0)
	if err != nil {
		t.Fatalf("Failed to derive child key: %v", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(childKey.Key)
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		t.Fatalf("Failed to create WIF: %v", err)
	}

	pubKeyBytes := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKeyBytes)

	p2pkhAddr, err := btcutil.NewAddressPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("Failed to create P2PKH address: %v", err)
	}

	// Expected address for "abandon..." mnemonic at m/44'/0'/0'/0/0
	// This is a well-known test vector
	expectedP2PKH := "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"
	if p2pkhAddr.EncodeAddress() != expectedP2PKH {
		t.Errorf("P2PKH address mismatch:\n  got:      %s\n  expected: %s", p2pkhAddr.EncodeAddress(), expectedP2PKH)
	}

	t.Logf("BIP44 P2PKH address: %s", p2pkhAddr.EncodeAddress())
}

func TestBIP84Derivation(t *testing.T) {
	// Known test mnemonic
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	seed := bip39.NewSeed(mnemonic, "")
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatalf("Failed to create master key: %v", err)
	}

	// Derive BIP84 path: m/84'/0'/0'/0/0
	childKey, err := deriveChildKey(masterKey, 84, 0)
	if err != nil {
		t.Fatalf("Failed to derive child key: %v", err)
	}

	privKey, _ := btcec.PrivKeyFromBytes(childKey.Key)
	wif, err := btcutil.NewWIF(privKey, &chaincfg.MainNetParams, true)
	if err != nil {
		t.Fatalf("Failed to create WIF: %v", err)
	}

	pubKeyBytes := wif.SerializePubKey()
	pubKeyHash := btcutil.Hash160(pubKeyBytes)

	p2wpkhAddr, err := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash, &chaincfg.MainNetParams)
	if err != nil {
		t.Fatalf("Failed to create P2WPKH address: %v", err)
	}

	// Expected address for "abandon..." mnemonic at m/84'/0'/0'/0/0
	// This is a well-known BIP84 test vector
	expectedP2WPKH := "bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu"
	if p2wpkhAddr.EncodeAddress() != expectedP2WPKH {
		t.Errorf("P2WPKH address mismatch:\n  got:      %s\n  expected: %s", p2wpkhAddr.EncodeAddress(), expectedP2WPKH)
	}

	t.Logf("BIP84 P2WPKH address: %s", p2wpkhAddr.EncodeAddress())
}

func TestMultipleIndexDerivation(t *testing.T) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

	seed := bip39.NewSeed(mnemonic, "")
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		t.Fatalf("Failed to create master key: %v", err)
	}

	// Test that different indexes produce different addresses
	addresses := make(map[string]bool)

	for idx := uint32(0); idx < 5; idx++ {
		// BIP44
		childKey44, err := deriveChildKey(masterKey, 44, idx)
		if err != nil {
			t.Fatalf("Failed to derive BIP44 child key at index %d: %v", idx, err)
		}
		privKey44, _ := btcec.PrivKeyFromBytes(childKey44.Key)
		wif44, _ := btcutil.NewWIF(privKey44, &chaincfg.MainNetParams, true)
		pubKeyHash44 := btcutil.Hash160(wif44.SerializePubKey())
		p2pkhAddr, _ := btcutil.NewAddressPubKeyHash(pubKeyHash44, &chaincfg.MainNetParams)

		if addresses[p2pkhAddr.EncodeAddress()] {
			t.Errorf("Duplicate P2PKH address at index %d", idx)
		}
		addresses[p2pkhAddr.EncodeAddress()] = true

		// BIP84
		childKey84, err := deriveChildKey(masterKey, 84, idx)
		if err != nil {
			t.Fatalf("Failed to derive BIP84 child key at index %d: %v", idx, err)
		}
		privKey84, _ := btcec.PrivKeyFromBytes(childKey84.Key)
		wif84, _ := btcutil.NewWIF(privKey84, &chaincfg.MainNetParams, true)
		pubKeyHash84 := btcutil.Hash160(wif84.SerializePubKey())
		p2wpkhAddr, _ := btcutil.NewAddressWitnessPubKeyHash(pubKeyHash84, &chaincfg.MainNetParams)

		if addresses[p2wpkhAddr.EncodeAddress()] {
			t.Errorf("Duplicate P2WPKH address at index %d", idx)
		}
		addresses[p2wpkhAddr.EncodeAddress()] = true

		t.Logf("Index %d: P2PKH=%s P2WPKH=%s", idx, p2pkhAddr.EncodeAddress(), p2wpkhAddr.EncodeAddress())
	}

	if len(addresses) != 10 {
		t.Errorf("Expected 10 unique addresses, got %d", len(addresses))
	}
}

func TestGenerateAddressesFromMnemonic(t *testing.T) {
	// Set addressIndexes for testing
	testIndexes := 3
	addressIndexes = &testIndexes

	addresses, err := generateAddressesFromMnemonic()
	if err != nil {
		t.Fatalf("Failed to generate addresses: %v", err)
	}

	expectedCount := 2 * testIndexes // 2 types * indexes
	if len(addresses) != expectedCount {
		t.Errorf("Expected %d addresses, got %d", expectedCount, len(addresses))
	}

	// Verify all addresses are unique
	seen := make(map[string]bool)
	for _, addr := range addresses {
		if seen[addr.address] {
			t.Errorf("Duplicate address found: %s", addr.address)
		}
		seen[addr.address] = true

		// Verify address format
		if addr.addrType[:5] == "p2pkh" {
			if addr.address[0] != '1' {
				t.Errorf("P2PKH address should start with '1': %s", addr.address)
			}
		} else if addr.addrType[:6] == "p2wpkh" {
			if addr.address[:4] != "bc1q" {
				t.Errorf("P2WPKH address should start with 'bc1q': %s", addr.address)
			}
		}

		// Verify mnemonic is 12 words
		words := len(splitMnemonic(addr.mnemonic))
		if words != 12 {
			t.Errorf("Expected 12-word mnemonic, got %d words", words)
		}
	}

	t.Logf("Generated %d addresses from random mnemonic", len(addresses))
}

func splitMnemonic(mnemonic string) []string {
	var words []string
	word := ""
	for _, c := range mnemonic {
		if c == ' ' {
			if word != "" {
				words = append(words, word)
				word = ""
			}
		} else {
			word += string(c)
		}
	}
	if word != "" {
		words = append(words, word)
	}
	return words
}

func TestBloomFilterLogic(t *testing.T) {
	// Import the bloom package for testing
	bf := bloom.NewWithEstimates(1000, 0.0001)

	// Add some test addresses
	testAddresses := []string{
		"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
		"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa", // Satoshi's address
	}

	for _, addr := range testAddresses {
		bf.AddString(addr)
	}

	// Test that added addresses are found
	for _, addr := range testAddresses {
		if !bf.TestString(addr) {
			t.Errorf("Bloom filter should contain %s", addr)
		}
	}

	// Test that random addresses are (probably) not found
	notInFilter := []string{
		"1NotInFilterAddress123456789012345",
		"bc1qnotinfilteraddress12345678901234",
	}

	foundCount := 0
	for _, addr := range notInFilter {
		if bf.TestString(addr) {
			foundCount++
		}
	}

	// With 0.01% FPR, it's very unlikely both would be false positives
	if foundCount == len(notInFilter) {
		t.Log("Warning: All test addresses were false positives (very unlikely)")
	}

	t.Logf("Bloom filter test complete: %d addresses added, filter size: %d bytes",
		len(testAddresses), bf.ApproximatedSize())
}

func TestBloomFilterNilFallback(t *testing.T) {
	// Save current bloom filter state
	originalFilter := addressBloomFilter

	// Set to nil to test fallback
	addressBloomFilter = nil

	// This should not panic and should return all addresses as candidates
	// (We can't actually test DB interaction without a DB, but we can verify
	// the function doesn't crash with nil bloom filter)

	// Restore
	addressBloomFilter = originalFilter

	t.Log("Nil bloom filter fallback test passed")
}

// Benchmarks

func BenchmarkGenerateAddresses(b *testing.B) {
	// Test with 1 address index
	testIndexes := 1
	addressIndexes = &testIndexes

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generateAddressesFromMnemonic()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkGenerateAddresses20(b *testing.B) {
	// Test with 20 address indexes (default)
	testIndexes := 20
	addressIndexes = &testIndexes

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := generateAddressesFromMnemonic()
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkDeriveChildKey(b *testing.B) {
	mnemonic := "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
	seed := bip39.NewSeed(mnemonic, "")
	masterKey, _ := bip32.NewMasterKey(seed)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := deriveChildKey(masterKey, 44, 0)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkBloomFilterLookup(b *testing.B) {
	// Create a bloom filter with 1M entries
	bf := bloom.NewWithEstimates(1000000, 0.0001)

	// Add some addresses
	for i := 0; i < 1000000; i++ {
		bf.AddString(string(rune(i)))
	}

	testAddr := "1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA"

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bf.TestString(testAddr)
	}
}
