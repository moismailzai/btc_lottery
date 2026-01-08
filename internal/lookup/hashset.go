package lookup

import (
	"encoding/binary"
	"sort"
	"sync"
)

// AddressHashSet provides O(log n) lookup for Bitcoin addresses using sorted hash prefixes.
// Uses first 8 bytes of address string as uint64 key for fast comparison.
type AddressHashSet struct {
	// Sorted array of 8-byte hash prefixes for binary search
	hashes []uint64

	// Full addresses indexed by hash prefix for match verification
	// Multiple addresses can have same prefix (rare but possible)
	fullAddresses map[uint64][]string

	mu sync.RWMutex
}

// NewAddressHashSet creates a new hash set with the given capacity hint.
func NewAddressHashSet(capacity int) *AddressHashSet {
	return &AddressHashSet{
		hashes:        make([]uint64, 0, capacity),
		fullAddresses: make(map[uint64][]string, capacity),
	}
}

// addressToHash converts first 8 bytes of address to uint64.
// This is sufficient for prefix matching; collisions are resolved via fullAddresses map.
func addressToHash(addr string) uint64 {
	if len(addr) < 8 {
		// Pad short addresses (shouldn't happen with real BTC addresses)
		padded := make([]byte, 8)
		copy(padded, addr)
		return binary.BigEndian.Uint64(padded)
	}
	return binary.BigEndian.Uint64([]byte(addr[:8]))
}

// AddBatch adds multiple addresses efficiently (unsorted).
// Call Finalize() after all addresses are added.
func (h *AddressHashSet) AddBatch(addresses []string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	for _, addr := range addresses {
		hash := addressToHash(addr)
		h.hashes = append(h.hashes, hash)
		h.fullAddresses[hash] = append(h.fullAddresses[hash], addr)
	}
}

// Add adds a single address.
func (h *AddressHashSet) Add(addr string) {
	h.mu.Lock()
	defer h.mu.Unlock()

	hash := addressToHash(addr)
	h.hashes = append(h.hashes, hash)
	h.fullAddresses[hash] = append(h.fullAddresses[hash], addr)
}

// Finalize sorts the hash array for binary search.
// Must be called after all addresses are added.
func (h *AddressHashSet) Finalize() {
	h.mu.Lock()
	defer h.mu.Unlock()

	// Sort hashes for binary search
	sort.Slice(h.hashes, func(i, j int) bool {
		return h.hashes[i] < h.hashes[j]
	})

	// Remove duplicates (same prefix can appear multiple times)
	if len(h.hashes) > 0 {
		unique := h.hashes[:1]
		for i := 1; i < len(h.hashes); i++ {
			if h.hashes[i] != unique[len(unique)-1] {
				unique = append(unique, h.hashes[i])
			}
		}
		h.hashes = unique
	}
}

// Contains checks if an address exists in the set.
// Returns true if found, along with any matching full addresses.
func (h *AddressHashSet) Contains(addr string) bool {
	hash := addressToHash(addr)

	h.mu.RLock()
	defer h.mu.RUnlock()

	// Binary search for hash prefix
	idx := sort.Search(len(h.hashes), func(i int) bool {
		return h.hashes[i] >= hash
	})

	if idx >= len(h.hashes) || h.hashes[idx] != hash {
		return false
	}

	// Hash prefix found - verify against full addresses
	fullAddrs := h.fullAddresses[hash]
	for _, fullAddr := range fullAddrs {
		if fullAddr == addr {
			return true
		}
	}

	return false
}

// ContainsBatch checks multiple addresses and returns a map of matches.
// More efficient than calling Contains repeatedly.
func (h *AddressHashSet) ContainsBatch(addresses []string) map[string]bool {
	result := make(map[string]bool)

	h.mu.RLock()
	defer h.mu.RUnlock()

	for _, addr := range addresses {
		hash := addressToHash(addr)

		// Binary search
		idx := sort.Search(len(h.hashes), func(i int) bool {
			return h.hashes[i] >= hash
		})

		if idx < len(h.hashes) && h.hashes[idx] == hash {
			// Verify full address
			for _, fullAddr := range h.fullAddresses[hash] {
				if fullAddr == addr {
					result[addr] = true
					break
				}
			}
		}
	}

	return result
}

// Len returns the number of unique hash prefixes.
func (h *AddressHashSet) Len() int {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return len(h.hashes)
}

// TotalAddresses returns the total number of addresses (including duplicates from same prefix).
func (h *AddressHashSet) TotalAddresses() int {
	h.mu.RLock()
	defer h.mu.RUnlock()

	total := 0
	for _, addrs := range h.fullAddresses {
		total += len(addrs)
	}
	return total
}

// Hashes returns a copy of the sorted hash array (for GPU transfer).
func (h *AddressHashSet) Hashes() []uint64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	result := make([]uint64, len(h.hashes))
	copy(result, h.hashes)
	return result
}

// MemoryUsage returns approximate memory usage in bytes.
func (h *AddressHashSet) MemoryUsage() int64 {
	h.mu.RLock()
	defer h.mu.RUnlock()

	// Hash array: 8 bytes per entry
	hashMem := int64(len(h.hashes) * 8)

	// Full addresses map: estimate based on average address length
	var addrMem int64
	for _, addrs := range h.fullAddresses {
		for _, addr := range addrs {
			addrMem += int64(len(addr) + 16) // string header overhead
		}
	}

	return hashMem + addrMem
}
