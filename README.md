# Winternitz One-Time Signature Scheme

This crate provides a memory-efficient implementation of the Winternitz One-Time Signature (WOTS) scheme and its enhanced version WOTS+. The implementation is designed to avoid any heap allocations, making it suitable for embedded and resource-constrained environments.

## Features

- Stack-based implementation using fixed-size arrays
- Zero heap allocations during key generation, signing, and verification
- Support for both standard WOTS and WOTS+ schemes
- Configurable security parameters with const generics
- Comprehensive benchmark suite using Criterion

## Usage

Basic usage for the standard WOTS:

```rust
use winternitz::WinternitzOTS;

// Create a WOTS instance with security parameter n=32 bytes and capacity for L=80 chains
let mut wots = WinternitzOTS::<32, 80>::new(16)?;

// Generate key pair
wots.generate_keys()?;

// Sign a message
let message = b"Message to sign";
let mut signature = [[0u8; 32]; 80];
wots.sign(message, &mut signature)?;

// Verify the signature
let is_valid = wots.verify(message, &signature)?;
assert!(is_valid);
```

Usage of the enhanced WOTS+:

```rust
use winternitz::WinternitzOTSPlus;

// Create a WOTS+ instance with security parameter n=32 bytes and capacity for L=80 chains
let mut wots_plus = WinternitzOTSPlus::<32, 80>::new(16)?;

// Generate key pair
wots_plus.generate_keys()?;

// Sign a message
let message = b"Message to sign";
let mut signature = [[0u8; 32]; 80];
wots_plus.sign(message, &mut signature)?;

// Verify the signature
let is_valid = wots_plus.verify(message, &signature)?;
assert!(is_valid);
```

## Performance

Run benchmarks:

```
cargo bench
```

The benchmarks measure the performance of key generation, signing, and verification for both WOTS and WOTS+.

## About Winternitz One-Time Signatures

The Winternitz One-Time Signature scheme is a post-quantum secure signature scheme based on hash functions. It provides a trade-off between signature size and computational cost by using a parameter 'w' that determines how many bits are processed together.

WOTS+ is an enhanced version that adds additional randomization to increase security against multi-target attacks.

## License

MIT License

## References

- [RFC 8391 - XMSS: eXtended Merkle Signature Scheme](https://datatracker.ietf.org/doc/html/rfc8391)
- [Post-Quantum Cryptography: SPHINCS+](https://sphincs.org/)