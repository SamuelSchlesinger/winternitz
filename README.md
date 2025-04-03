# Winternitz One-Time Signature Scheme

A Rust implementation of the Winternitz One-Time Signature (WOTS) scheme and
its enhanced variant, WOTS+. This crate provides memory-efficient
implementations that avoid heap allocations, making them suitable for embedded
and resource-constrained environments.

## Overview

The Winternitz One-Time Signature scheme is a post-quantum secure signature
algorithm based on hash functions. Unlike traditional signature schemes like
RSA or ECDSA, WOTS is designed to remain secure even against attackers with
quantum computers.

As the name suggests, each key pair should only be used *once* to sign a single
message. Reusing a key pair severely compromises security and may allow
signature forgery.

## Features

- **Memory Efficiency:** Uses fixed-size arrays to avoid heap allocations
- **Parameter Flexibility:** Configurable security parameters with const
  generics
- **Dual Implementation:** Includes both standard WOTS and enhanced WOTS+
  variants
- **Comprehensive Error Handling:** Detailed error types for robust application
  integration
- **Thorough Test Suite:** Extensive tests and benchmarks to ensure correctness
  and performance

## Implementation Details

The library provides two main structs:

1. `WinternitzOTS<const N: usize, const L: usize>` - The standard Winternitz One-Time Signature implementation
2. `WinternitzOTSPlus<const N: usize, const L: usize>` - The enhanced Winternitz One-Time Signature Plus implementation

Where:
- `N` is the security parameter (hash output length in bytes)
- `L` is the maximum number of hash chains needed for signatures

The implementation uses SHA-256 as the underlying hash function.

## Security Considerations

### Parameters

- **Winternitz Parameter (w)**: Controls the time-signature size trade-off.
  Must be a power of 2 (typically 16).
- **Security Parameter (N)**: Size of the hash output in bytes (typically 32
  for 256-bit security).
- **Chain Length (L)**: Must be large enough to accommodate the base-w
  representation of both the message digest and checksum (typically 80 for
N=32, w=16).

### WOTS vs. WOTS+

The WOTS+ variant provides enhanced security against multi-target attacks by
introducing additional randomization through a public seed. If security is your
primary concern, prefer WOTS+ over standard WOTS.

## Usage

### Basic Example with Standard WOTS

```rust
use winternitz::WinternitzOTS;

// Create a WOTS instance with N=32 bytes, L=80 chains, w=16
let mut wots = WinternitzOTS::<32, 80>::new(16)?;

// Generate key pair
wots.generate_keys()?;

// Sign a message
let message = b"This is a message to be signed";
let mut signature = [[0u8; 32]; 80];
wots.sign(message, &mut signature)?;

// Verify the signature
let is_valid = wots.verify(message, &signature)?;
assert!(is_valid);

// Verification should fail for a different message
let different_message = b"This is a different message";
let is_valid = wots.verify(different_message, &signature)?;
assert!(!is_valid);
```

### Enhanced Security with WOTS+

```rust
use winternitz::WinternitzOTSPlus;

// Create a WOTS+ instance with N=32 bytes, L=80 chains, w=16
let mut wots_plus = WinternitzOTSPlus::<32, 80>::new(16)?;

// Generate key pair
wots_plus.generate_keys()?;

// Sign a message
let message = b"This is a message to be signed";
let mut signature = [[0u8; 32]; 80];
wots_plus.sign(message, &mut signature)?;

// Verify the signature
let is_valid = wots_plus.verify(message, &signature)?;
assert!(is_valid);

// Access public key and public seed for transmission
let public_key = wots_plus.get_public_key()?;
let public_seed = wots_plus.get_public_seed()?;
```

## Performance

The crate includes benchmarks to measure the performance of key generation,
signing, and verification for both WOTS and WOTS+. Run the benchmarks with:

```bash
cargo bench
```

## License

This project is licensed under the MIT License.

## References

- [RFC 8391 - XMSS: eXtended Merkle Signature Scheme](https://datatracker.ietf.org/doc/html/rfc8391)
- [Post-Quantum Cryptography: SPHINCS+](https://sphincs.org/)
- Buchmann, J., Dahmen, E., & Hülsing, A. (2011). XMSS - A Practical Forward Secure Signature Scheme based on Minimal Security Assumptions.
