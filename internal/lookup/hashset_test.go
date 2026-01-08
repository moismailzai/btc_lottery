package lookup

import (
	"fmt"
	"math/rand"
	"testing"
)

func TestAddressHashSet_Basic(t *testing.T) {
	h := NewAddressHashSet(100)

	addresses := []string{
		"1LqBGSKuX5yYUonjxT5qGfpUsXKYYWeabA",
		"bc1qcr8te4kr609gcawutmrza0j4xv80jy8z306fyu",
		"37VucYSaXLCAsxYyAPfbSi9eh4iEcbShgf",
		"bc1p5cyxnuxmeuwuvkwfem96lqzszd02n6xdcjrs20cac6yqjjwudpxqkedrcr",
	}

	h.AddBatch(addresses)
	h.Finalize()

	// Test positive lookups
	for _, addr := range addresses {
		if !h.Contains(addr) {
			t.Errorf("Expected to find %s", addr)
		}
	}

	// Test negative lookups
	notPresent := []string{
		"1NotInSetAddress12345678901234567",
		"bc1qnotinset12345678901234567890",
	}
	for _, addr := range notPresent {
		if h.Contains(addr) {
			t.Errorf("Did not expect to find %s", addr)
		}
	}
}

func TestAddressHashSet_BatchContains(t *testing.T) {
	h := NewAddressHashSet(100)

	addresses := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		"1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2",
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
	}

	h.AddBatch(addresses)
	h.Finalize()

	// Check batch with mix of present and not present
	check := []string{
		"1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa",
		"1NotPresent123456789012345678901",
		"3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy",
	}

	result := h.ContainsBatch(check)

	if !result["1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"] {
		t.Error("Expected to find Satoshi's address")
	}
	if result["1NotPresent123456789012345678901"] {
		t.Error("Did not expect to find non-existent address")
	}
	if !result["3J98t1WpEZ73CNmQviecrnyiWrnqRhWNLy"] {
		t.Error("Expected to find P2SH address")
	}
}

func TestAddressHashSet_HashCollision(t *testing.T) {
	// Two addresses with same first 8 bytes (extremely rare but possible)
	h := NewAddressHashSet(10)

	// These share prefix "1Same8By"
	addr1 := "1Same8BytePrefix_A12345678901234"
	addr2 := "1Same8BytePrefix_B98765432109876"

	h.Add(addr1)
	h.Add(addr2)
	h.Finalize()

	// Both should be findable
	if !h.Contains(addr1) {
		t.Errorf("Expected to find %s", addr1)
	}
	if !h.Contains(addr2) {
		t.Errorf("Expected to find %s", addr2)
	}

	// Different address with same prefix should not be found
	addr3 := "1Same8BytePrefix_C00000000000000"
	if h.Contains(addr3) {
		t.Errorf("Did not expect to find %s", addr3)
	}
}

func generateRandomAddresses(n int) []string {
	addresses := make([]string, n)
	for i := 0; i < n; i++ {
		// Generate random address-like string
		prefixes := []string{"1", "3", "bc1q", "bc1p"}
		prefix := prefixes[rand.Intn(len(prefixes))]
		suffix := make([]byte, 30)
		for j := range suffix {
			suffix[j] = "0123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"[rand.Intn(58)]
		}
		addresses[i] = prefix + string(suffix)
	}
	return addresses
}

func BenchmarkHashSet_Add1M(b *testing.B) {
	addresses := generateRandomAddresses(1_000_000)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h := NewAddressHashSet(1_000_000)
		h.AddBatch(addresses)
		h.Finalize()
	}
}

func BenchmarkHashSet_Contains(b *testing.B) {
	addresses := generateRandomAddresses(1_000_000)
	h := NewAddressHashSet(1_000_000)
	h.AddBatch(addresses)
	h.Finalize()

	// Pick random addresses to look up
	lookups := make([]string, 1000)
	for i := 0; i < 500; i++ {
		lookups[i] = addresses[rand.Intn(len(addresses))] // Present
	}
	for i := 500; i < 1000; i++ {
		lookups[i] = fmt.Sprintf("1NotPresent%d", i) // Not present
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, addr := range lookups {
			h.Contains(addr)
		}
	}
}

func BenchmarkHashSet_ContainsBatch(b *testing.B) {
	addresses := generateRandomAddresses(1_000_000)
	h := NewAddressHashSet(1_000_000)
	h.AddBatch(addresses)
	h.Finalize()

	// Pick random addresses to look up
	lookups := make([]string, 1000)
	for i := 0; i < 500; i++ {
		lookups[i] = addresses[rand.Intn(len(addresses))]
	}
	for i := 500; i < 1000; i++ {
		lookups[i] = fmt.Sprintf("1NotPresent%d", i)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		h.ContainsBatch(lookups)
	}
}

func BenchmarkHashSet_Contains50M(b *testing.B) {
	// Simulate 50M addresses
	if testing.Short() {
		b.Skip("Skipping 50M benchmark in short mode")
	}

	addresses := generateRandomAddresses(50_000_000)
	h := NewAddressHashSet(50_000_000)
	h.AddBatch(addresses)
	h.Finalize()

	// Random lookups
	lookups := make([]string, 80)
	for i := range lookups {
		if i%2 == 0 {
			lookups[i] = addresses[rand.Intn(len(addresses))]
		} else {
			lookups[i] = fmt.Sprintf("1NotPresent%d", i)
		}
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		for _, addr := range lookups {
			h.Contains(addr)
		}
	}
}
