// BTC Lottery GPU Kernel
// Adapted from CudaBrainSecp (https://github.com/XopMC/CudaBrainSecp)
// and VanitySearch (https://github.com/JeanLucPons/VanitySearch)
// License: GPL-3.0

#include <cuda.h>
#include <cuda_runtime.h>
#include <device_launch_parameters.h>
#include <stdint.h>

// Include the proven implementations from VanitySearch/CudaBrainSecp
#include "GPUMath.h"
#include "GPUHash.h"

// GTable configuration - 16 chunks of 65536 points each
// Total: 16 * 65536 * 32 bytes per coordinate = ~33.5MB per coordinate (~67MB total)
#define NUM_GTABLE_CHUNK 16
#define NUM_GTABLE_VALUE 65536
#define SIZE_GTABLE_POINT 32  // Each point coordinate is 32 bytes (256 bits)
#define COUNT_GTABLE_POINTS (NUM_GTABLE_CHUNK * NUM_GTABLE_VALUE)

// Hash sizes
#define SIZE_HASH160 20
#define SIZE_PRIV_KEY 32

// Thread indexing
#define IDX_CUDA_THREAD ((blockIdx.x * blockDim.x) + threadIdx.x)

// Starting index for each chunk in the GTable (precomputed to save multiplication)
__device__ __constant__ int CHUNK_FIRST_ELEMENT[NUM_GTABLE_CHUNK] = {
    65536*0,  65536*1,  65536*2,  65536*3,
    65536*4,  65536*5,  65536*6,  65536*7,
    65536*8,  65536*9,  65536*10, 65536*11,
    65536*12, 65536*13, 65536*14, 65536*15,
};

// Secp256k1 Point Multiplication using GTable lookup
// Takes 32-byte privKey + gTable and outputs 64-byte public key [qx,qy]
// The private key is interpreted as 16 little-endian uint16 chunks
__device__ void _PointMultiSecp256k1(uint64_t *qx, uint64_t *qy,
                                      uint16_t *privKey,
                                      uint8_t *gTableX, uint8_t *gTableY) {
    int chunk = 0;
    uint64_t qz[5] = {1, 0, 0, 0, 0};

    // Find the first non-zero chunk to initialize [qx,qy]
    for (; chunk < NUM_GTABLE_CHUNK; chunk++) {
        if (privKey[chunk] > 0) {
            int index = (CHUNK_FIRST_ELEMENT[chunk] + (privKey[chunk] - 1)) * SIZE_GTABLE_POINT;
            memcpy(qx, gTableX + index, SIZE_GTABLE_POINT);
            memcpy(qy, gTableY + index, SIZE_GTABLE_POINT);
            chunk++;
            break;
        }
    }

    // Add the remaining non-zero chunks together using Jacobian point addition
    for (; chunk < NUM_GTABLE_CHUNK; chunk++) {
        if (privKey[chunk] > 0) {
            uint64_t gx[4];
            uint64_t gy[4];

            int index = (CHUNK_FIRST_ELEMENT[chunk] + (privKey[chunk] - 1)) * SIZE_GTABLE_POINT;

            memcpy(gx, gTableX + index, SIZE_GTABLE_POINT);
            memcpy(gy, gTableY + index, SIZE_GTABLE_POINT);

            // Use the _PointAddSecp256k1 from GPUMath.h (Jacobian coordinates)
            _PointAddSecp256k1(qx, qy, qz, gx, gy);
        }
    }

    // Convert from Jacobian to affine coordinates by multiplying by z^(-1)
    _ModInv(qz);
    _ModMult(qx, qz);
    _ModMult(qy, qz);
}

// Extract first 8 bytes from Hash160 as uint64 for fast comparison
// Uses big-endian ordering (most significant bytes first for proper sorting)
__device__ __forceinline__ uint64_t _GetHashPrefix(uint8_t *hash160) {
    return ((uint64_t)hash160[0] << 56) |
           ((uint64_t)hash160[1] << 48) |
           ((uint64_t)hash160[2] << 40) |
           ((uint64_t)hash160[3] << 32) |
           ((uint64_t)hash160[4] << 24) |
           ((uint64_t)hash160[5] << 16) |
           ((uint64_t)hash160[6] << 8) |
           ((uint64_t)hash160[7]);
}

// Main kernel: compute public keys from private keys and check against hash table
// Each thread processes one private key, computes its public key + Hash160,
// and binary searches against the sorted hash table
extern "C" __global__ void btc_lottery_kernel(
    const uint8_t *privKeys,          // Input: batch of 32-byte private keys
    int numKeys,                       // Number of private keys to process
    uint8_t *gTableX,                  // GTable X coordinates (precomputed points)
    uint8_t *gTableY,                  // GTable Y coordinates
    const uint64_t *sortedHashes,      // Sorted hash160 prefixes (first 8 bytes each)
    int hashCount,                     // Number of hashes in the lookup table
    int *matchFlags,                   // Output: 1 if match found, 0 otherwise
    uint8_t *matchPrivKeys,            // Output: matching private keys (32 bytes each)
    uint8_t *matchHashes               // Output: full hash160 for matches (20 bytes each)
) {
    int idx = IDX_CUDA_THREAD;
    if (idx >= numKeys) return;

    // Initialize output to no match
    matchFlags[idx] = 0;

    // Load private key (32 bytes)
    uint8_t privKey[SIZE_PRIV_KEY];
    for (int i = 0; i < SIZE_PRIV_KEY; i++) {
        privKey[i] = privKeys[idx * SIZE_PRIV_KEY + i];
    }

    // Compute public key from private key using GTable lookup
    uint64_t qx[4], qy[4];
    _PointMultiSecp256k1(qx, qy, (uint16_t*)privKey, gTableX, gTableY);

    // Compute Hash160 for compressed public key (prefix 02/03 + X coordinate)
    uint8_t hash160[SIZE_HASH160];
    uint8_t parity = (uint8_t)(qy[0] & 1);  // 0 = even (02), 1 = odd (03)
    _GetHash160Comp(qx, parity, hash160);

    // Extract first 8 bytes as hash prefix for binary search
    uint64_t hashPrefix = _GetHashPrefix(hash160);

    // Binary search in sorted hash array
    int found = _BinarySearch((uint64_t*)sortedHashes, hashCount, hashPrefix);

    if (found >= 0) {
        // Match found! Save the results
        matchFlags[idx] = 1;

        // Save the private key
        for (int i = 0; i < SIZE_PRIV_KEY; i++) {
            matchPrivKeys[idx * SIZE_PRIV_KEY + i] = privKey[i];
        }

        // Save the full hash160
        for (int i = 0; i < SIZE_HASH160; i++) {
            matchHashes[idx * SIZE_HASH160 + i] = hash160[i];
        }
    }

    // Also check uncompressed public key (less common but some old wallets use it)
    _GetHash160(qx, qy, hash160);
    hashPrefix = _GetHashPrefix(hash160);

    found = _BinarySearch((uint64_t*)sortedHashes, hashCount, hashPrefix);

    if (found >= 0) {
        matchFlags[idx] = 2;  // 2 indicates uncompressed match

        for (int i = 0; i < SIZE_PRIV_KEY; i++) {
            matchPrivKeys[idx * SIZE_PRIV_KEY + i] = privKey[i];
        }
        for (int i = 0; i < SIZE_HASH160; i++) {
            matchHashes[idx * SIZE_HASH160 + i] = hash160[i];
        }
    }
}

// Simpler kernel for testing GTable loading - verify first point is G
extern "C" __global__ void test_gtable_kernel(
    uint8_t *gTableX,
    uint8_t *gTableY,
    uint64_t *outputX,  // Output: first 4 uint64 of X
    uint64_t *outputY   // Output: first 4 uint64 of Y
) {
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        // Copy first point (should be G)
        memcpy(outputX, gTableX, 32);
        memcpy(outputY, gTableY, 32);
    }
}

// Test kernel for verifying point multiplication
// Multiplies a known private key and outputs the result for verification
extern "C" __global__ void test_point_mult_kernel(
    uint8_t *privKey,      // Input: 32-byte private key
    uint8_t *gTableX,
    uint8_t *gTableY,
    uint64_t *outputX,     // Output: public key X
    uint64_t *outputY,     // Output: public key Y
    uint8_t *outputHash    // Output: Hash160
) {
    if (threadIdx.x == 0 && blockIdx.x == 0) {
        uint64_t qx[4], qy[4];

        _PointMultiSecp256k1(qx, qy, (uint16_t*)privKey, gTableX, gTableY);

        memcpy(outputX, qx, 32);
        memcpy(outputY, qy, 32);

        uint8_t parity = (uint8_t)(qy[0] & 1);
        _GetHash160Comp(qx, parity, outputHash);
    }
}
