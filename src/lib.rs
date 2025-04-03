//! # Winternitz One-Time Signature Schemes
//!
//! This crate provides memory-efficient implementations of the Winternitz One-Time
//! Signature (WOTS) scheme and its enhanced variant, WOTS+. Both implementations are designed
//! to operate without heap allocations, making them suitable for embedded and resource-constrained
//! environments.
//!
//! ## Background
//!
//! The Winternitz One-Time Signature scheme is a post-quantum secure signature scheme based on
//! hash functions. It offers a configurable trade-off between signature size and computational
//! cost through the Winternitz parameter 'w', which determines how many bits are processed together.
//!
//! WOTS+ is an enhanced version that introduces additional randomization to increase security
//! against multi-target attacks.
//!
//! ## Security Considerations
//!
//! As the name suggests, Winternitz signature keys must only be used once. Reusing a key pair for
//! multiple signatures severely compromises security and may allow signature forgery.
//!
//! ## Implementation Features
//!
//! - Stack-based implementation using fixed-size arrays
//! - Zero heap allocations during key generation, signing, and verification
//! - Configurable security parameters with const generics
//! - Comprehensive error handling
//!
//! ## Basic Usage
//!
//! ```rust
//! use winternitz::WinternitzOTS;
//!
//! // Create a WOTS instance with security parameter n=32 bytes and capacity for L=80 chains
//! let mut wots = WinternitzOTS::<32, 80>::new(16)?;
//!
//! // Generate key pair
//! wots.generate_keys()?;
//!
//! // Sign a message
//! let message = b"Message to sign";
//! let mut signature = [[0u8; 32]; 80];
//! wots.sign(message, &mut signature)?;
//!
//! // Verify the signature
//! let is_valid = wots.verify(message, &signature)?;
//! assert!(is_valid);
//! # Ok::<(), winternitz::WotsError>(())
//! ```

use sha2::{Sha256, Digest};
use rand::{RngCore, rngs::OsRng};
use std::fmt;

/// Maximum security parameter (hash output length in bytes).
/// This matches the output size of SHA-256.
pub const MAX_N: usize = 32;

/// Maximum length of chains for most practical use cases.
/// This value is sufficient for most practical applications with a reasonable
/// Winternitz parameter.
pub const MAX_LEN: usize = 128;

/// Errors that can occur during Winternitz one-time signature operations.
#[derive(Debug)]
pub enum WotsError {
    /// The Winternitz parameter 'w' is invalid. Must be a power of 2.
    InvalidWinternitzParameter,
    /// Operation attempted before keys were generated.
    KeysNotGenerated,
    /// The provided signature has an invalid length or format.
    InvalidSignature,
    /// Invalid parameters were provided to the hash chain function.
    InvalidChainParameters,
    /// Signature verification failed.
    Verification,
    /// The provided buffer size is insufficient for the operation.
    BufferTooSmall,
}

impl fmt::Display for WotsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WotsError::InvalidWinternitzParameter => write!(f, "Winternitz parameter must be a power of 2"),
            WotsError::KeysNotGenerated => write!(f, "Keys not generated. Call generate_keys() first"),
            WotsError::InvalidSignature => write!(f, "Invalid signature length"),
            WotsError::InvalidChainParameters => write!(f, "Invalid chain parameters"),
            WotsError::Verification => write!(f, "Signature verification failed"),
            WotsError::BufferTooSmall => write!(f, "Buffer too small for operation"),
        }
    }
}

impl std::error::Error for WotsError {}

/// Standard Winternitz One-Time Signature (WOTS) scheme implementation.
///
/// This struct implements the classic Winternitz One-Time Signature scheme using fixed-size arrays
/// to avoid heap allocations, making it suitable for resource-constrained environments.
///
/// The implementation uses SHA-256 as the underlying hash function.
///
/// ## Type Parameters
///
/// * `N` - Security parameter representing the hash output length in bytes.
///   Common values are 32 (for 256-bit security).
///
/// * `L` - Maximum number of hash chains needed for signatures.
///   This value is calculated based on the Winternitz parameter 'w' and must be
///   large enough to accommodate both the message digest and checksum. A value of 80
///   is sufficient for N=32 and w=16.
///
/// ## Security Considerations
///
/// As with any one-time signature scheme, each key pair MUST only be used to sign
/// a single message. Reusing a key pair severely compromises security.
pub struct WinternitzOTS<const N: usize, const L: usize> {
    /// Winternitz parameter (must be a power of 2)
    w: u32,                           
    /// Log base 2 of w
    log_w: u32,                       
    /// Number of w-bit blocks needed for message digest
    len_1: usize,                     
    /// Number of w-bit blocks needed for checksum
    len_2: usize,                     
    /// Total number of blocks (len_1 + len_2)
    len: usize,                       
    /// Private key (if generated)
    private_key: Option<[[u8; N]; L]>,
    /// Public key (if generated)
    public_key: Option<[[u8; N]; L]>,
}

impl<const N: usize, const L: usize> WinternitzOTS<N, L> {
    /// Creates a new Winternitz One-Time Signature instance.
    ///
    /// # Parameters
    ///
    /// * `w` - The Winternitz parameter. Must be a power of 2 (e.g., 2, 4, 8, 16, etc.).
    ///   Higher values reduce signature size but increase computation time.
    ///   A typical value is 16.
    ///
    /// # Returns
    ///
    /// A new `WinternitzOTS` instance on success, or a `WotsError` if:
    /// - The Winternitz parameter is not a power of 2
    /// - The buffer sizes (N or L) are too small for the chosen parameters
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTS;
    ///
    /// // Create a WOTS instance with w=16, N=32 bytes (256-bit), and L=80 chains
    /// let wots = WinternitzOTS::<32, 80>::new(16)?;
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn new(w: u32) -> Result<Self, WotsError> {
        // Validate parameters
        if w < 2 || (w & (w - 1)) != 0 {
            return Err(WotsError::InvalidWinternitzParameter);
        }
        
        if N == 0 || L == 0 {
            return Err(WotsError::BufferTooSmall);
        }
        
        // Calculate derived parameters
        let log_w = w.trailing_zeros();
        
        // Number of w-bit blocks needed to represent n-byte message digest
        let len_1 = ((8 * N) as f64 / log_w as f64).ceil() as usize;
        
        // Number of w-bit blocks needed for checksum
        let len_2 = ((((len_1 * (w as usize - 1)) as f64).log2() / log_w as f64).floor() as usize) + 1;
        
        // Total number of blocks
        let len = len_1 + len_2;
        
        if len > L {
            return Err(WotsError::BufferTooSmall);
        }
        
        Ok(WinternitzOTS {
            w,
            log_w,
            len_1,
            len_2,
            len,
            private_key: None,
            public_key: None,
        })
    }
    
    /// Internal hash function implementation using SHA-256.
    ///
    /// Maps arbitrary input data to a fixed-size digest of length N.
    ///
    /// # Parameters
    ///
    /// * `data` - The input data to hash
    /// * `output` - Buffer to store the hash output
    fn hash(&self, data: &[u8], output: &mut [u8; N]) {
        let mut hasher = Sha256::new();
        hasher.update(data);
        output.copy_from_slice(&hasher.finalize()[..N]);
    }
    
    /// Applies the hash chain function for the specified number of iterations.
    ///
    /// # Parameters
    ///
    /// * `x` - The initial hash chain value
    /// * `start` - The starting index for the chain (0 ≤ start < w)
    /// * `steps` - The number of chain steps to apply (0 ≤ steps ≤ w-start)
    /// * `result` - Buffer to store the resulting hash value
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an `InvalidChainParameters` error if the parameters are invalid.
    fn chain(&self, x: &[u8; N], start: u32, steps: u32, result: &mut [u8; N]) -> Result<(), WotsError> {
        if start >= self.w || steps > (self.w - start) {
            return Err(WotsError::InvalidChainParameters);
        }
        
        // Copy input to result buffer
        result.copy_from_slice(x);
        
        // Apply hash chain
        let mut buffer = [0u8; 2]; // For chain index
        for i in start..(start + steps) {
            // Prepend chain index to prevent potential multi-target attacks
            buffer.copy_from_slice(&(i as u16).to_be_bytes());
            
            // Create hash input with chain index followed by current state
            let mut hasher = Sha256::new();
            hasher.update(&buffer);
            hasher.update(&*result);
            
            // Update result
            result.copy_from_slice(&hasher.finalize()[..N]);
        }
        
        Ok(())
    }
    
    /// Generates a new private-public key pair.
    ///
    /// The private key consists of L random N-byte values.
    /// The public key is derived by applying the hash chain function (w-1) times
    /// to each private key element.
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a `WotsError` if there's an error during key generation.
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTS;
    ///
    /// let mut wots = WinternitzOTS::<32, 80>::new(16)?;
    /// wots.generate_keys()?;
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn generate_keys(&mut self) -> Result<(), WotsError> {
        // Initialize private key array with random bytes
        let mut private_key: [[u8; N]; L] = unsafe { std::mem::zeroed() };
        
        // Generate random private keys
        for i in 0..self.len {
            OsRng.fill_bytes(&mut private_key[i]);
        }
        
        // Initialize public key array
        let mut public_key: [[u8; N]; L] = unsafe { std::mem::zeroed() };
        
        // Generate public keys by applying hash chains
        for i in 0..self.len {
            self.chain(&private_key[i], 0, self.w - 1, &mut public_key[i])?;
        }
        
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        
        Ok(())
    }
    
    /// Converts a message digest to base w representation.
    ///
    /// Splits the message digest into blocks of log₂(w) bits and converts each block
    /// to an integer between 0 and w-1.
    ///
    /// # Parameters
    ///
    /// * `msg_digest` - The message digest to convert
    /// * `result` - Buffer to store the base w representation
    fn convert_to_base_w(&self, msg_digest: &[u8; N], result: &mut [u32; L]) {
        let bits_per_digit = self.log_w as usize;
        let mut index = 0;
        
        // Process each byte of the message digest
        for &byte in msg_digest.iter() {
            let mut bits_remaining = 8;
            while bits_remaining >= bits_per_digit && index < self.len_1 {
                bits_remaining -= bits_per_digit;
                // Extract bits_per_digit bits and convert to integer
                let digit = (byte >> bits_remaining) & (self.w - 1) as u8;
                result[index] = digit as u32;
                index += 1;
            }
        }
        
        // Pad if needed
        while index < self.len_1 {
            result[index] = 0;
            index += 1;
        }
    }
    
    /// Computes the checksum for a base w message representation.
    ///
    /// The checksum is designed to prevent forgery attacks and ensure that
    /// reducing the value of one message block would require increasing the
    /// value of another, making it computationally infeasible to forge signatures.
    ///
    /// # Parameters
    ///
    /// * `msg_base_w` - The message in base w representation
    /// * `checksum_base_w` - Buffer to store the checksum in base w
    fn compute_checksum(&self, msg_base_w: &[u32; L], checksum_base_w: &mut [u32; L]) {
        // Compute checksum (sum of w-1 - digit for each digit)
        let mut checksum: u32 = 0;
        for i in 0..self.len_1 {
            checksum += (self.w - 1) - msg_base_w[i];
        }
        
        // Convert checksum to base w representation
        let mut index = 0;
        let mut remaining_checksum = checksum;
        
        while (remaining_checksum > 0 || index < self.len_2) && index < self.len_2 {
            checksum_base_w[index] = remaining_checksum % self.w;
            remaining_checksum /= self.w;
            index += 1;
        }
        
        // Pad if needed
        while index < self.len_2 {
            checksum_base_w[index] = 0;
            index += 1;
        }
    }
    
    /// Combines message base-w representation and checksum into a single array.
    ///
    /// # Parameters
    ///
    /// * `msg_base_w` - The message in base w representation
    /// * `checksum_base_w` - The checksum in base w representation
    /// * `combined` - Buffer to store the combined representation
    fn combine_msg_and_checksum(
        &self,
        msg_base_w: &[u32; L],
        checksum_base_w: &[u32; L],
        combined: &mut [u32; L]
    ) {
        // Copy message digits
        for i in 0..self.len_1 {
            combined[i] = msg_base_w[i];
        }
        
        // Copy checksum digits
        for i in 0..self.len_2 {
            combined[self.len_1 + i] = checksum_base_w[i];
        }
    }
    
    /// Signs a message using the Winternitz one-time signature scheme.
    ///
    /// # Parameters
    ///
    /// * `message` - The message to sign
    /// * `signature` - Buffer to store the signature
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a `WotsError` if there's an error during signing.
    ///
    /// # Security
    ///
    /// The private key should only be used to sign ONE message. Reusing the key
    /// for multiple signatures may allow signature forgery.
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTS;
    ///
    /// let mut wots = WinternitzOTS::<32, 80>::new(16)?;
    /// wots.generate_keys()?;
    ///
    /// let message = b"Message to sign";
    /// let mut signature = [[0u8; 32]; 80];
    /// wots.sign(message, &mut signature)?;
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn sign(&self, message: &[u8], signature: &mut [[u8; N]; L]) -> Result<(), WotsError> {
        let private_key = match &self.private_key {
            Some(key) => key,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        // Hash the message
        let mut msg_digest = [0u8; N];
        self.hash(message, &mut msg_digest);
        
        // Convert to base w representation
        let mut msg_base_w = [0u32; L];
        self.convert_to_base_w(&msg_digest, &mut msg_base_w);
        
        // Compute checksum and convert to base w
        let mut checksum_base_w = [0u32; L];
        self.compute_checksum(&msg_base_w, &mut checksum_base_w);
        
        // Combine message and checksum digits
        let mut combined = [0u32; L];
        self.combine_msg_and_checksum(&msg_base_w, &checksum_base_w, &mut combined);
        
        // Generate signature: for each digit, apply hash chain 'digit' times
        for i in 0..self.len {
            self.chain(&private_key[i], 0, combined[i], &mut signature[i])?;
        }
        
        Ok(())
    }
    
    /// Verifies a Winternitz one-time signature.
    ///
    /// # Parameters
    ///
    /// * `message` - The message to verify
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature is valid, `Ok(false)` if it's invalid,
    /// or a `WotsError` if there's an error during verification.
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTS;
    ///
    /// let mut wots = WinternitzOTS::<32, 80>::new(16)?;
    /// wots.generate_keys()?;
    ///
    /// let message = b"Message to sign";
    /// let mut signature = [[0u8; 32]; 80];
    /// wots.sign(message, &mut signature)?;
    ///
    /// let is_valid = wots.verify(message, &signature)?;
    /// assert!(is_valid);
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn verify(&self, message: &[u8], signature: &[[u8; N]; L]) -> Result<bool, WotsError> {
        let public_key = match &self.public_key {
            Some(key) => key,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        // Hash the message
        let mut msg_digest = [0u8; N];
        self.hash(message, &mut msg_digest);
        
        // Convert to base w representation
        let mut msg_base_w = [0u32; L];
        self.convert_to_base_w(&msg_digest, &mut msg_base_w);
        
        // Compute checksum and convert to base w
        let mut checksum_base_w = [0u32; L];
        self.compute_checksum(&msg_base_w, &mut checksum_base_w);
        
        // Combine message and checksum digits
        let mut combined = [0u32; L];
        self.combine_msg_and_checksum(&msg_base_w, &checksum_base_w, &mut combined);
        
        // Verify signature: for each digit, complete the hash chain to w-1 steps
        let mut computed_pk = [0u8; N];
        
        for i in 0..self.len {
            let remaining_steps = self.w - 1 - combined[i];
            self.chain(&signature[i], combined[i], remaining_steps, &mut computed_pk)?;
            
            // Check if computed public key element matches the actual public key element
            if computed_pk != public_key[i] {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Gets the public key.
    ///
    /// # Returns
    ///
    /// A reference to the public key on success, or a `KeysNotGenerated` error
    /// if the keys haven't been generated yet.
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTS;
    ///
    /// let mut wots = WinternitzOTS::<32, 80>::new(16)?;
    /// wots.generate_keys()?;
    ///
    /// let public_key = wots.get_public_key()?;
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn get_public_key(&self) -> Result<&[[u8; N]; L], WotsError> {
        match &self.public_key {
            Some(key) => Ok(key),
            None => Err(WotsError::KeysNotGenerated),
        }
    }
}

/// Enhanced Winternitz One-Time Signature Plus (WOTS+) implementation.
///
/// WOTS+ is an enhanced version of the Winternitz One-Time Signature scheme that provides
/// additional security against multi-target attacks through the use of randomized hash functions.
/// This implementation uses keyed hash functions with a public seed for this randomization.
///
/// The implementation uses fixed-size arrays to avoid heap allocations, making it suitable
/// for resource-constrained environments.
///
/// ## Type Parameters
///
/// * `N` - Security parameter representing the hash output length in bytes.
///   Common values are 32 (for 256-bit security).
///
/// * `L` - Maximum number of hash chains needed for signatures.
///   This value is calculated based on the Winternitz parameter 'w' and must be
///   large enough to accommodate both the message digest and checksum. A value of 80
///   is sufficient for N=32 and w=16.
///
/// ## Security Considerations
///
/// As with any one-time signature scheme, each key pair MUST only be used to sign
/// a single message. Reusing a key pair severely compromises security.
///
/// Compared to the standard WOTS scheme, WOTS+ provides enhanced security against
/// multi-target attacks by using a public seed for hash function randomization.
pub struct WinternitzOTSPlus<const N: usize, const L: usize> {
    /// Winternitz parameter (must be a power of 2)
    w: u32,                           
    /// Log base 2 of w
    log_w: u32,                       
    /// Number of w-bit blocks needed for message digest
    len_1: usize,                     
    /// Number of w-bit blocks needed for checksum
    len_2: usize,                     
    /// Total number of blocks (len_1 + len_2)
    len: usize,                       
    /// Private key (if generated)
    private_key: Option<[[u8; N]; L]>,
    /// Public key (if generated)
    public_key: Option<[[u8; N]; L]>,
    /// Public seed for hash function randomization (if generated)
    public_seed: Option<[u8; N]>,
    /// Secret seed for deterministic private key generation (if generated)
    secret_seed: Option<[u8; N]>,
}

impl<const N: usize, const L: usize> WinternitzOTSPlus<N, L> {
    /// Creates a new Winternitz One-Time Signature Plus instance.
    ///
    /// # Parameters
    ///
    /// * `w` - The Winternitz parameter. Must be a power of 2 (e.g., 2, 4, 8, 16, etc.).
    ///   Higher values reduce signature size but increase computation time.
    ///   A typical value is 16.
    ///
    /// # Returns
    ///
    /// A new `WinternitzOTSPlus` instance on success, or a `WotsError` if:
    /// - The Winternitz parameter is not a power of 2
    /// - The buffer sizes (N or L) are too small for the chosen parameters
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTSPlus;
    ///
    /// // Create a WOTS+ instance with w=16, N=32 bytes (256-bit), and L=80 chains
    /// let wots = WinternitzOTSPlus::<32, 80>::new(16)?;
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn new(w: u32) -> Result<Self, WotsError> {
        // Validate parameters
        if w < 2 || (w & (w - 1)) != 0 {
            return Err(WotsError::InvalidWinternitzParameter);
        }
        
        if N == 0 || L == 0 {
            return Err(WotsError::BufferTooSmall);
        }
        
        // Calculate derived parameters
        let log_w = w.trailing_zeros();
        
        // Number of w-bit blocks needed to represent n-byte message digest
        let len_1 = ((8 * N) as f64 / log_w as f64).ceil() as usize;
        
        // Number of w-bit blocks needed for checksum
        let len_2 = ((((len_1 * (w as usize - 1)) as f64).log2() / log_w as f64).floor() as usize) + 1;
        
        // Total number of blocks
        let len = len_1 + len_2;
        
        if len > L {
            return Err(WotsError::BufferTooSmall);
        }
        
        Ok(WinternitzOTSPlus {
            w,
            log_w,
            len_1,
            len_2,
            len,
            private_key: None,
            public_key: None,
            public_seed: None,
            secret_seed: None,
        })
    }
    
    /// Internal hash function implementation using SHA-256.
    ///
    /// Maps arbitrary input data to a fixed-size digest of length N.
    ///
    /// # Parameters
    ///
    /// * `data` - The input data to hash
    /// * `output` - Buffer to store the hash output
    fn hash(&self, data: &[u8], output: &mut [u8; N]) {
        let mut hasher = Sha256::new();
        hasher.update(data);
        output.copy_from_slice(&hasher.finalize()[..N]);
    }
    
    /// Pseudorandom function used for generating private key elements from the secret seed.
    ///
    /// # Parameters
    ///
    /// * `key` - The secret seed
    /// * `addr` - Address value (used to generate different outputs for each chain)
    /// * `output` - Buffer to store the PRF output
    fn prf(&self, key: &[u8; N], addr: u32, output: &mut [u8; N]) {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(&addr.to_be_bytes());
        output.copy_from_slice(&hasher.finalize()[..N]);
    }
    
    /// Keyed hash function for the WOTS+ chain.
    ///
    /// This is a key component of WOTS+ that enhances security against multi-target attacks
    /// by using a public seed and address values to create different hash functions for
    /// each chain position.
    ///
    /// # Parameters
    ///
    /// * `public_seed` - The public seed for hash function randomization
    /// * `addr` - Address value identifying the hash chain
    /// * `chain_pos` - Position within the hash chain
    /// * `data` - Input data to hash
    /// * `output` - Buffer to store the hash output
    fn hash_with_seed(&self, public_seed: &[u8; N], addr: u32, chain_pos: u32, data: &[u8; N], output: &mut [u8; N]) {
        let mut hasher = Sha256::new();
        hasher.update(public_seed);
        hasher.update(&addr.to_be_bytes());
        hasher.update(&chain_pos.to_be_bytes());
        hasher.update(data);
        output.copy_from_slice(&hasher.finalize()[..N]);
    }
    
    /// Applies the hash chain function for WOTS+ with the specified number of iterations.
    ///
    /// This function differs from the standard WOTS chain function by using the keyed
    /// hash function with the public seed for each iteration.
    ///
    /// # Parameters
    ///
    /// * `x` - The initial hash chain value
    /// * `start` - The starting index for the chain (0 ≤ start < w)
    /// * `steps` - The number of chain steps to apply (0 ≤ steps ≤ w-start)
    /// * `addr` - Address value identifying the hash chain
    /// * `result` - Buffer to store the resulting hash value
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or an error if the parameters are invalid or the public seed hasn't been generated.
    fn chain(&self, x: &[u8; N], start: u32, steps: u32, addr: u32, result: &mut [u8; N]) -> Result<(), WotsError> {
        if start >= self.w || steps > (self.w - start) {
            return Err(WotsError::InvalidChainParameters);
        }
        
        let public_seed = match &self.public_seed {
            Some(seed) => seed,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        // Copy input to result buffer
        result.copy_from_slice(x);
        
        // Apply hash chain
        for i in start..(start + steps) {
            let mut tmp = [0u8; N];
            // Create a temporary borrowing of result
            let result_ref = &*result;
            self.hash_with_seed(public_seed, addr, i, result_ref, &mut tmp);
            // Copy the result back
            result.copy_from_slice(&tmp);
        }
        
        Ok(())
    }
    
    /// Generates a new private-public key pair for WOTS+.
    ///
    /// Unlike the standard WOTS, WOTS+ generates:
    /// 1. A random public seed for hash function randomization
    /// 2. A random secret seed for deterministic private key generation
    /// 3. Private key elements derived from the secret seed using a PRF
    /// 4. Public key elements by applying the hash chain function to each private key element
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a `WotsError` if there's an error during key generation.
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTSPlus;
    ///
    /// let mut wots = WinternitzOTSPlus::<32, 80>::new(16)?;
    /// wots.generate_keys()?;
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn generate_keys(&mut self) -> Result<(), WotsError> {
        // Generate public seed for randomization
        let mut public_seed = [0u8; N];
        OsRng.fill_bytes(&mut public_seed);
        self.public_seed = Some(public_seed);
        
        // Generate secret seed
        let mut secret_seed = [0u8; N];
        OsRng.fill_bytes(&mut secret_seed);
        self.secret_seed = Some(secret_seed);
        
        // Generate private key using PRF
        let mut private_key: [[u8; N]; L] = unsafe { std::mem::zeroed() };
        let secret_seed_ref = self.secret_seed.as_ref().unwrap();
        
        for i in 0..self.len {
            self.prf(secret_seed_ref, i as u32, &mut private_key[i]);
        }
        
        // Generate public key: apply hash chain w-1 times to each private key element
        let mut public_key: [[u8; N]; L] = unsafe { std::mem::zeroed() };
        
        for i in 0..self.len {
            self.chain(&private_key[i], 0, self.w - 1, i as u32, &mut public_key[i])?;
        }
        
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        
        Ok(())
    }
    
    /// Converts a message digest to base w representation.
    ///
    /// Splits the message digest into blocks of log₂(w) bits and converts each block
    /// to an integer between 0 and w-1.
    ///
    /// # Parameters
    ///
    /// * `msg_digest` - The message digest to convert
    /// * `result` - Buffer to store the base w representation
    fn convert_to_base_w(&self, msg_digest: &[u8; N], result: &mut [u32; L]) {
        let bits_per_digit = self.log_w as usize;
        let mut index = 0;
        
        // Process each byte of the message digest
        for &byte in msg_digest.iter() {
            let mut bits_remaining = 8;
            while bits_remaining >= bits_per_digit && index < self.len_1 {
                bits_remaining -= bits_per_digit;
                // Extract bits_per_digit bits and convert to integer
                let digit = (byte >> bits_remaining) & (self.w - 1) as u8;
                result[index] = digit as u32;
                index += 1;
            }
        }
        
        // Pad if needed
        while index < self.len_1 {
            result[index] = 0;
            index += 1;
        }
    }
    
    /// Computes the checksum for a base w message representation.
    ///
    /// The checksum is designed to prevent forgery attacks and ensure that
    /// reducing the value of one message block would require increasing the
    /// value of another, making it computationally infeasible to forge signatures.
    ///
    /// # Parameters
    ///
    /// * `msg_base_w` - The message in base w representation
    /// * `checksum_base_w` - Buffer to store the checksum in base w
    fn compute_checksum(&self, msg_base_w: &[u32; L], checksum_base_w: &mut [u32; L]) {
        // Compute checksum (sum of w-1 - digit for each digit)
        let mut checksum: u32 = 0;
        for i in 0..self.len_1 {
            checksum += (self.w - 1) - msg_base_w[i];
        }
        
        // Convert checksum to base w representation
        let mut index = 0;
        let mut remaining_checksum = checksum;
        
        while (remaining_checksum > 0 || index < self.len_2) && index < self.len_2 {
            checksum_base_w[index] = remaining_checksum % self.w;
            remaining_checksum /= self.w;
            index += 1;
        }
        
        // Pad if needed
        while index < self.len_2 {
            checksum_base_w[index] = 0;
            index += 1;
        }
    }
    
    /// Combines message base-w representation and checksum into a single array.
    ///
    /// # Parameters
    ///
    /// * `msg_base_w` - The message in base w representation
    /// * `checksum_base_w` - The checksum in base w representation
    /// * `combined` - Buffer to store the combined representation
    fn combine_msg_and_checksum(
        &self,
        msg_base_w: &[u32; L],
        checksum_base_w: &[u32; L],
        combined: &mut [u32; L]
    ) {
        // Copy message digits
        for i in 0..self.len_1 {
            combined[i] = msg_base_w[i];
        }
        
        // Copy checksum digits
        for i in 0..self.len_2 {
            combined[self.len_1 + i] = checksum_base_w[i];
        }
    }
    
    /// Signs a message using the Winternitz one-time signature plus scheme.
    ///
    /// # Parameters
    ///
    /// * `message` - The message to sign
    /// * `signature` - Buffer to store the signature
    ///
    /// # Returns
    ///
    /// `Ok(())` on success, or a `WotsError` if there's an error during signing.
    ///
    /// # Security
    ///
    /// The private key should only be used to sign ONE message. Reusing the key
    /// for multiple signatures may allow signature forgery.
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTSPlus;
    ///
    /// let mut wots = WinternitzOTSPlus::<32, 80>::new(16)?;
    /// wots.generate_keys()?;
    ///
    /// let message = b"Message to sign";
    /// let mut signature = [[0u8; 32]; 80];
    /// wots.sign(message, &mut signature)?;
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn sign(&self, message: &[u8], signature: &mut [[u8; N]; L]) -> Result<(), WotsError> {
        let private_key = match &self.private_key {
            Some(key) => key,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        // Hash the message
        let mut msg_digest = [0u8; N];
        self.hash(message, &mut msg_digest);
        
        // Convert to base w representation
        let mut msg_base_w = [0u32; L];
        self.convert_to_base_w(&msg_digest, &mut msg_base_w);
        
        // Compute checksum and convert to base w
        let mut checksum_base_w = [0u32; L];
        self.compute_checksum(&msg_base_w, &mut checksum_base_w);
        
        // Combine message and checksum digits
        let mut combined = [0u32; L];
        self.combine_msg_and_checksum(&msg_base_w, &checksum_base_w, &mut combined);
        
        // Generate signature: for each digit, apply hash chain 'digit' times
        for i in 0..self.len {
            self.chain(&private_key[i], 0, combined[i], i as u32, &mut signature[i])?;
        }
        
        Ok(())
    }
    
    /// Verifies a Winternitz one-time signature plus.
    ///
    /// # Parameters
    ///
    /// * `message` - The message to verify
    /// * `signature` - The signature to verify
    ///
    /// # Returns
    ///
    /// `Ok(true)` if the signature is valid, `Ok(false)` if it's invalid,
    /// or a `WotsError` if there's an error during verification.
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTSPlus;
    ///
    /// let mut wots = WinternitzOTSPlus::<32, 80>::new(16)?;
    /// wots.generate_keys()?;
    ///
    /// let message = b"Message to sign";
    /// let mut signature = [[0u8; 32]; 80];
    /// wots.sign(message, &mut signature)?;
    ///
    /// let is_valid = wots.verify(message, &signature)?;
    /// assert!(is_valid);
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn verify(&self, message: &[u8], signature: &[[u8; N]; L]) -> Result<bool, WotsError> {
        let public_key = match &self.public_key {
            Some(key) => key,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        // Hash the message
        let mut msg_digest = [0u8; N];
        self.hash(message, &mut msg_digest);
        
        // Convert to base w representation
        let mut msg_base_w = [0u32; L];
        self.convert_to_base_w(&msg_digest, &mut msg_base_w);
        
        // Compute checksum and convert to base w
        let mut checksum_base_w = [0u32; L];
        self.compute_checksum(&msg_base_w, &mut checksum_base_w);
        
        // Combine message and checksum digits
        let mut combined = [0u32; L];
        self.combine_msg_and_checksum(&msg_base_w, &checksum_base_w, &mut combined);
        
        // Verify signature: for each digit, complete the hash chain to w-1 steps
        let mut computed_pk = [0u8; N];
        
        for i in 0..self.len {
            let remaining_steps = self.w - 1 - combined[i];
            self.chain(&signature[i], combined[i], remaining_steps, i as u32, &mut computed_pk)?;
            
            // Check if computed public key element matches the actual public key element
            if computed_pk != public_key[i] {
                return Ok(false);
            }
        }
        
        Ok(true)
    }
    
    /// Gets the public key.
    ///
    /// # Returns
    ///
    /// A reference to the public key on success, or a `KeysNotGenerated` error
    /// if the keys haven't been generated yet.
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTSPlus;
    ///
    /// let mut wots = WinternitzOTSPlus::<32, 80>::new(16)?;
    /// wots.generate_keys()?;
    ///
    /// let public_key = wots.get_public_key()?;
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn get_public_key(&self) -> Result<&[[u8; N]; L], WotsError> {
        match &self.public_key {
            Some(key) => Ok(key),
            None => Err(WotsError::KeysNotGenerated),
        }
    }
    
    /// Gets the public seed.
    ///
    /// The public seed is a random value used for hash function randomization.
    /// It must be transmitted along with the public key to allow signature verification.
    ///
    /// # Returns
    ///
    /// A reference to the public seed on success, or a `KeysNotGenerated` error
    /// if the keys haven't been generated yet.
    ///
    /// # Examples
    ///
    /// ```
    /// use winternitz::WinternitzOTSPlus;
    ///
    /// let mut wots = WinternitzOTSPlus::<32, 80>::new(16)?;
    /// wots.generate_keys()?;
    ///
    /// let public_seed = wots.get_public_seed()?;
    /// # Ok::<(), winternitz::WotsError>(())
    /// ```
    pub fn get_public_seed(&self) -> Result<&[u8; N], WotsError> {
        match &self.public_seed {
            Some(seed) => Ok(seed),
            None => Err(WotsError::KeysNotGenerated),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    // Basic functionality tests for WinternitzOTS
    #[test]
    fn test_winternitz_ots() -> Result<(), Box<dyn std::error::Error>> {
        // Create a Winternitz OTS instance with w=16
        let mut wots = WinternitzOTS::<32, 80>::new(16)?;
        
        // Generate keys
        wots.generate_keys()?;
        
        // Message to sign
        let message = b"This is a test message to be signed with Winternitz OTS";
        
        // Sign the message
        let mut signature = [[0u8; 32]; 80];
        wots.sign(message, &mut signature)?;
        
        // Verify the signature
        let is_valid = wots.verify(message, &signature)?;
        assert!(is_valid);
        
        // Try to verify with a different message (should fail)
        let modified_message = b"This is a MODIFIED message to be signed with Winternitz OTS";
        let is_valid = wots.verify(modified_message, &signature)?;
        assert!(!is_valid);
        
        Ok(())
    }

    // Basic functionality tests for WinternitzOTSPlus
    #[test]
    fn test_winternitz_ots_plus() -> Result<(), Box<dyn std::error::Error>> {
        // Create a WOTS+ instance with w=16
        let mut wots_plus = WinternitzOTSPlus::<32, 80>::new(16)?;
        
        // Generate keys
        wots_plus.generate_keys()?;
        
        // Message to sign
        let message = b"This is a test message to be signed with Winternitz OTS";
        
        // Sign the message
        let mut signature_plus = [[0u8; 32]; 80];
        wots_plus.sign(message, &mut signature_plus)?;
        
        // Verify the signature
        let is_valid = wots_plus.verify(message, &signature_plus)?;
        assert!(is_valid);
        
        // Try to verify with a different message (should fail)
        let modified_message = b"This is a MODIFIED message to be signed with Winternitz OTS";
        let is_valid = wots_plus.verify(modified_message, &signature_plus)?;
        assert!(!is_valid);
        
        Ok(())
    }

    // Test various Winternitz parameter values for WinternitzOTS
    #[test]
    fn test_winternitz_parameters() -> Result<(), Box<dyn std::error::Error>> {
        // Test valid Winternitz parameters (powers of 2)
        // For a smaller hash size of 8 bytes, we can use w=2 safely
        let wots_2 = WinternitzOTS::<8, 128>::new(2);
        assert!(wots_2.is_ok());
        
        // Test invalid Winternitz parameters (not powers of 2)
        for w in [0, 1, 3, 5, 6, 9].iter() {
            let wots = WinternitzOTS::<8, 128>::new(*w);
            assert!(wots.is_err());
            if let Err(err) = wots {
                assert!(matches!(err, WotsError::InvalidWinternitzParameter));
            }
        }
        
        Ok(())
    }
    
    // Test various Winternitz parameter values for WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_parameters() -> Result<(), Box<dyn std::error::Error>> {
        // Test valid Winternitz parameters (powers of 2)
        // For a smaller hash size of 8 bytes, we can use w=2 safely
        let wots_2 = WinternitzOTSPlus::<8, 128>::new(2);
        assert!(wots_2.is_ok());
        
        // Test invalid Winternitz parameters (not powers of 2)
        for w in [0, 1, 3, 5, 6, 9].iter() {
            let wots = WinternitzOTSPlus::<8, 128>::new(*w);
            assert!(wots.is_err());
            if let Err(err) = wots {
                assert!(matches!(err, WotsError::InvalidWinternitzParameter));
            }
        }
        
        Ok(())
    }

    // Test buffer size constraints for WinternitzOTS
    #[test]
    fn test_winternitz_buffer_size() -> Result<(), Box<dyn std::error::Error>> {
        // Test with insufficient buffer size
        let wots_small = WinternitzOTS::<32, 10>::new(16);
        assert!(wots_small.is_err());
        if let Err(err) = wots_small {
            assert!(matches!(err, WotsError::BufferTooSmall));
        }
        
        // Test with zero buffer size
        let wots_zero = WinternitzOTS::<32, 0>::new(16);
        assert!(wots_zero.is_err());
        if let Err(err) = wots_zero {
            assert!(matches!(err, WotsError::BufferTooSmall));
        }
        
        // Test with zero hash size
        let wots_zero_hash = WinternitzOTS::<0, 80>::new(16);
        assert!(wots_zero_hash.is_err());
        if let Err(err) = wots_zero_hash {
            assert!(matches!(err, WotsError::BufferTooSmall));
        }
        
        Ok(())
    }
    
    // Test buffer size constraints for WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_buffer_size() -> Result<(), Box<dyn std::error::Error>> {
        // Test with insufficient buffer size
        let wots_small = WinternitzOTSPlus::<32, 10>::new(16);
        assert!(wots_small.is_err());
        if let Err(err) = wots_small {
            assert!(matches!(err, WotsError::BufferTooSmall));
        }
        
        // Test with zero buffer size
        let wots_zero = WinternitzOTSPlus::<32, 0>::new(16);
        assert!(wots_zero.is_err());
        if let Err(err) = wots_zero {
            assert!(matches!(err, WotsError::BufferTooSmall));
        }
        
        // Test with zero hash size
        let wots_zero_hash = WinternitzOTSPlus::<0, 80>::new(16);
        assert!(wots_zero_hash.is_err());
        if let Err(err) = wots_zero_hash {
            assert!(matches!(err, WotsError::BufferTooSmall));
        }
        
        Ok(())
    }

    // Test signing without generating keys first for WinternitzOTS
    #[test]
    fn test_winternitz_sign_without_keys() -> Result<(), Box<dyn std::error::Error>> {
        let wots = WinternitzOTS::<32, 80>::new(16)?;
        let message = b"Test message";
        let mut signature = [[0u8; 32]; 80];
        
        let result = wots.sign(message, &mut signature);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::KeysNotGenerated));
        }
        
        Ok(())
    }
    
    // Test signing without generating keys first for WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_sign_without_keys() -> Result<(), Box<dyn std::error::Error>> {
        let wots = WinternitzOTSPlus::<32, 80>::new(16)?;
        let message = b"Test message";
        let mut signature = [[0u8; 32]; 80];
        
        let result = wots.sign(message, &mut signature);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::KeysNotGenerated));
        }
        
        Ok(())
    }

    // Test verifying without generating keys first for WinternitzOTS
    #[test]
    fn test_winternitz_verify_without_keys() -> Result<(), Box<dyn std::error::Error>> {
        let wots = WinternitzOTS::<32, 80>::new(16)?;
        let message = b"Test message";
        let signature = [[0u8; 32]; 80];
        
        let result = wots.verify(message, &signature);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::KeysNotGenerated));
        }
        
        Ok(())
    }
    
    // Test verifying without generating keys first for WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_verify_without_keys() -> Result<(), Box<dyn std::error::Error>> {
        let wots = WinternitzOTSPlus::<32, 80>::new(16)?;
        let message = b"Test message";
        let signature = [[0u8; 32]; 80];
        
        let result = wots.verify(message, &signature);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::KeysNotGenerated));
        }
        
        Ok(())
    }
    
    // Test signature tampering detection for WinternitzOTS
    #[test]
    fn test_winternitz_signature_tampering() -> Result<(), Box<dyn std::error::Error>> {
        const N: usize = 32;
        let mut wots = WinternitzOTS::<N, 80>::new(16)?;
        wots.generate_keys()?;
        
        let message = b"This is a test message for signature tampering detection";
        let mut signature = [[0u8; N]; 80];
        wots.sign(message, &mut signature)?;
        
        // Verify original signature
        let is_valid = wots.verify(message, &signature)?;
        assert!(is_valid);
        
        // Test tampering with various parts of the signature
        
        // 1. Tamper with the first byte of the first signature element
        let mut tampered_sig1 = signature;
        tampered_sig1[0][0] ^= 0xFF; // Flip all bits in the first byte
        let is_valid = wots.verify(message, &tampered_sig1)?;
        assert!(!is_valid, "Verification succeeded despite tampering with first byte");
        
        // 2. Tamper with the last byte of the last signature element
        let mut tampered_sig2 = signature;
        tampered_sig2[wots.len - 1][N - 1] ^= 0x01; // Flip one bit in the last byte
        let is_valid = wots.verify(message, &tampered_sig2)?;
        assert!(!is_valid, "Verification succeeded despite tampering with last byte");
        
        // 3. Tamper with a middle signature element
        let mut tampered_sig3 = signature;
        tampered_sig3[wots.len / 2][N / 2] ^= 0x10; // Flip one bit in the middle
        let is_valid = wots.verify(message, &tampered_sig3)?;
        assert!(!is_valid, "Verification succeeded despite tampering with middle element");
        
        // 4. Swap two signature elements
        let mut tampered_sig4 = signature;
        tampered_sig4.swap(0, 1); // Swap first two elements
        let is_valid = wots.verify(message, &tampered_sig4)?;
        assert!(!is_valid, "Verification succeeded despite swapping elements");
        
        Ok(())
    }
    
    // Test signature tampering detection for WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_signature_tampering() -> Result<(), Box<dyn std::error::Error>> {
        const N: usize = 32;
        let mut wots = WinternitzOTSPlus::<N, 80>::new(16)?;
        wots.generate_keys()?;
        
        let message = b"This is a test message for signature tampering detection";
        let mut signature = [[0u8; N]; 80];
        wots.sign(message, &mut signature)?;
        
        // Verify original signature
        let is_valid = wots.verify(message, &signature)?;
        assert!(is_valid);
        
        // Test tampering with various parts of the signature
        
        // 1. Tamper with the first byte of the first signature element
        let mut tampered_sig1 = signature;
        tampered_sig1[0][0] ^= 0xFF; // Flip all bits in the first byte
        let is_valid = wots.verify(message, &tampered_sig1)?;
        assert!(!is_valid, "Verification succeeded despite tampering with first byte");
        
        // 2. Tamper with the last byte of the last signature element
        let mut tampered_sig2 = signature;
        tampered_sig2[wots.len - 1][N - 1] ^= 0x01; // Flip one bit in the last byte
        let is_valid = wots.verify(message, &tampered_sig2)?;
        assert!(!is_valid, "Verification succeeded despite tampering with last byte");
        
        // 3. Tamper with a middle signature element
        let mut tampered_sig3 = signature;
        tampered_sig3[wots.len / 2][N / 2] ^= 0x10; // Flip one bit in the middle
        let is_valid = wots.verify(message, &tampered_sig3)?;
        assert!(!is_valid, "Verification succeeded despite tampering with middle element");
        
        // 4. Swap two signature elements
        let mut tampered_sig4 = signature;
        tampered_sig4.swap(0, 1); // Swap first two elements
        let is_valid = wots.verify(message, &tampered_sig4)?;
        assert!(!is_valid, "Verification succeeded despite swapping elements");
        
        Ok(())
    }
    
    // Test signing and verifying with different Winternitz parameters for WinternitzOTS
    #[test]
    fn test_winternitz_different_parameters() -> Result<(), Box<dyn std::error::Error>> {
        // Only test with w=2 to ensure we don't exceed buffer capacity
        let w = 2;
        // Use a much smaller hash size and larger buffer
        let mut wots = WinternitzOTS::<8, 128>::new(w)?;
        wots.generate_keys()?;
        
        let message = b"Testing with different Winternitz parameters";
        let mut signature = [[0u8; 8]; 128];
        wots.sign(message, &mut signature)?;
        
        let is_valid = wots.verify(message, &signature)?;
        assert!(is_valid, "Signature verification failed with w={}", w);
        
        // Modify message
        let modified = b"Modified message with different Winternitz parameters";
        let is_valid = wots.verify(modified, &signature)?;
        assert!(!is_valid, "Signature incorrectly verified modified message with w={}", w);
        
        Ok(())
    }
    
    // Test signing and verifying with different Winternitz parameters for WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_different_parameters() -> Result<(), Box<dyn std::error::Error>> {
        // Only test with w=2 to ensure we don't exceed buffer capacity
        let w = 2;
        // Use a much smaller hash size and larger buffer
        let mut wots = WinternitzOTSPlus::<8, 128>::new(w)?;
        wots.generate_keys()?;
        
        let message = b"Testing with different Winternitz parameters";
        let mut signature = [[0u8; 8]; 128];
        wots.sign(message, &mut signature)?;
        
        let is_valid = wots.verify(message, &signature)?;
        assert!(is_valid, "Signature verification failed with w={}", w);
        
        // Modify message
        let modified = b"Modified message with different Winternitz parameters";
        let is_valid = wots.verify(modified, &signature)?;
        assert!(!is_valid, "Signature incorrectly verified modified message with w={}", w);
        
        Ok(())
    }
    
    // Test signing and verifying with different message sizes for WinternitzOTS
    #[test]
    fn test_winternitz_different_message_sizes() -> Result<(), Box<dyn std::error::Error>> {
        let mut wots = WinternitzOTS::<32, 80>::new(16)?;
        wots.generate_keys()?;
        
        // Test with different message sizes
        let messages = [
            b"".as_slice(),                 // Empty message
            b"A".as_slice(),               // Single character
            b"Short message".as_slice(),   // Short message
            &[0u8; 64].as_slice(),          // Binary data 64 bytes
            &[0u8; 1024].as_slice(),        // Binary data 1KB
            &[0u8; 4096].as_slice(),        // Binary data 4KB
        ];
        
        for message in messages.iter() {
            let mut signature = [[0u8; 32]; 80];
            wots.sign(message, &mut signature)?;
            
            let is_valid = wots.verify(message, &signature)?;
            assert!(is_valid, "Signature verification failed for message of size {}", message.len());
            
            // Modify one byte of the message if it's not empty
            if !message.is_empty() {
                let mut modified = message.to_vec();
                modified[0] ^= 0x01; // Flip one bit in the first byte
                
                let is_valid = wots.verify(&modified, &signature)?;
                assert!(!is_valid, "Signature incorrectly verified modified message of size {}", message.len());
            }
        }
        
        Ok(())
    }
    
    // Test signing and verifying with different message sizes for WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_different_message_sizes() -> Result<(), Box<dyn std::error::Error>> {
        let mut wots = WinternitzOTSPlus::<32, 80>::new(16)?;
        wots.generate_keys()?;
        
        // Test with different message sizes
        let messages = [
            b"".as_slice(),                 // Empty message
            b"A".as_slice(),               // Single character
            b"Short message".as_slice(),   // Short message
            &[0u8; 64].as_slice(),          // Binary data 64 bytes
            &[0u8; 1024].as_slice(),        // Binary data 1KB
            &[0u8; 4096].as_slice(),        // Binary data 4KB
        ];
        
        for message in messages.iter() {
            let mut signature = [[0u8; 32]; 80];
            wots.sign(message, &mut signature)?;
            
            let is_valid = wots.verify(message, &signature)?;
            assert!(is_valid, "Signature verification failed for message of size {}", message.len());
            
            // Modify one byte of the message if it's not empty
            if !message.is_empty() {
                let mut modified = message.to_vec();
                modified[0] ^= 0x01; // Flip one bit in the first byte
                
                let is_valid = wots.verify(&modified, &signature)?;
                assert!(!is_valid, "Signature incorrectly verified modified message of size {}", message.len());
            }
        }
        
        Ok(())
    }

    // Test API functions on WinternitzOTS
    #[test]
    fn test_winternitz_api() -> Result<(), Box<dyn std::error::Error>> {
        let mut wots = WinternitzOTS::<32, 80>::new(16)?;
        
        // Test get_public_key before generating keys
        let result = wots.get_public_key();
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::KeysNotGenerated));
        }
        
        // Generate keys
        wots.generate_keys()?;
        
        // Test get_public_key after generating keys
        let pub_key = wots.get_public_key()?;
        assert_eq!(pub_key.len(), 80);
        
        Ok(())
    }
    
    // Test API functions on WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_api() -> Result<(), Box<dyn std::error::Error>> {
        let mut wots = WinternitzOTSPlus::<32, 80>::new(16)?;
        
        // Test get_public_key before generating keys
        let result = wots.get_public_key();
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::KeysNotGenerated));
        }
        
        // Test get_public_seed before generating keys
        let result = wots.get_public_seed();
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::KeysNotGenerated));
        }
        
        // Generate keys
        wots.generate_keys()?;
        
        // Test get_public_key after generating keys
        let pub_key = wots.get_public_key()?;
        assert_eq!(pub_key.len(), 80);
        
        // Test get_public_seed after generating keys
        let pub_seed = wots.get_public_seed()?;
        assert_eq!(pub_seed.len(), 32);
        
        Ok(())
    }
    
    // Test one-time nature of WinternitzOTS - reusing a key pair should be insecure
    #[test]
    fn test_winternitz_one_time_nature() -> Result<(), Box<dyn std::error::Error>> {
        let mut wots = WinternitzOTS::<32, 80>::new(16)?;
        wots.generate_keys()?;
        
        // Sign first message
        let message1 = b"First message to be signed";
        let mut signature1 = [[0u8; 32]; 80];
        wots.sign(message1, &mut signature1)?;
        
        // Verify first signature
        let is_valid = wots.verify(message1, &signature1)?;
        assert!(is_valid);
        
        // Sign second message with same key pair
        let message2 = b"Second message that should not be signed with same key";
        let mut signature2 = [[0u8; 32]; 80];
        wots.sign(message2, &mut signature2)?;
        
        // Verify second signature
        let is_valid = wots.verify(message2, &signature2)?;
        assert!(is_valid);
        
        // Now try to forge a third message by combining the two signatures
        // This is a simplified attack and might not work for all cases,
        // but it demonstrates the vulnerability of key reuse
        let message3 = b"Third message attempting to forge signature";
        let mut combined_sig = [[0u8; 32]; 80];
        
        // For simplicity, just use parts of both signatures
        // In a real attack, the attacker would be more sophisticated
        for i in 0..wots.len {
            if i % 2 == 0 {
                combined_sig[i] = signature1[i];
            } else {
                combined_sig[i] = signature2[i];
            }
        }
        
        // Verify with forged signature (should most likely fail, but demonstrates the risk)
        let forged_result = wots.verify(message3, &combined_sig)?;
        
        // We're not asserting a specific result here because successful forgery depends
        // on specific message patterns, but we're demonstrating that key reuse is dangerous
        println!("Forgery attack with key reuse resulted in verification: {}", forged_result);
        
        Ok(())
    }
    
    // Test one-time nature of WinternitzOTSPlus - reusing a key pair should be insecure
    #[test]
    fn test_winternitz_plus_one_time_nature() -> Result<(), Box<dyn std::error::Error>> {
        let mut wots = WinternitzOTSPlus::<32, 80>::new(16)?;
        wots.generate_keys()?;
        
        // Sign first message
        let message1 = b"First message to be signed";
        let mut signature1 = [[0u8; 32]; 80];
        wots.sign(message1, &mut signature1)?;
        
        // Verify first signature
        let is_valid = wots.verify(message1, &signature1)?;
        assert!(is_valid);
        
        // Sign second message with same key pair
        let message2 = b"Second message that should not be signed with same key";
        let mut signature2 = [[0u8; 32]; 80];
        wots.sign(message2, &mut signature2)?;
        
        // Verify second signature
        let is_valid = wots.verify(message2, &signature2)?;
        assert!(is_valid);
        
        // Now try to forge a third message by combining the two signatures
        // This is a simplified attack and might not work for all cases,
        // but it demonstrates the vulnerability of key reuse
        let message3 = b"Third message attempting to forge signature";
        let mut combined_sig = [[0u8; 32]; 80];
        
        // For simplicity, just use parts of both signatures
        // In a real attack, the attacker would be more sophisticated
        for i in 0..wots.len {
            if i % 2 == 0 {
                combined_sig[i] = signature1[i];
            } else {
                combined_sig[i] = signature2[i];
            }
        }
        
        // Verify with forged signature (should most likely fail, but demonstrates the risk)
        let forged_result = wots.verify(message3, &combined_sig)?;
        
        // We're not asserting a specific result here because successful forgery depends
        // on specific message patterns, but we're demonstrating that key reuse is dangerous
        println!("Forgery attack with key reuse resulted in verification: {}", forged_result);
        
        Ok(())
    }

    // Test chain function parameter validation for WinternitzOTS
    #[test]
    fn test_winternitz_chain_parameters() -> Result<(), Box<dyn std::error::Error>> {
        let wots = WinternitzOTS::<32, 80>::new(16)?;
        let input = [0u8; 32];
        let mut output = [0u8; 32];
        
        // Chain function doesn't require keys to be generated to validate parameters,
        // so don't test for KeysNotGenerated error
        
        // Invalid start parameter
        let result = wots.chain(&input, 16, 1, &mut output);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::InvalidChainParameters));
        }
        
        // Invalid steps parameter
        let result = wots.chain(&input, 10, 7, &mut output);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::InvalidChainParameters));
        }
        
        Ok(())
    }
    
    // Test chain function parameter validation for WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_chain_parameters() -> Result<(), Box<dyn std::error::Error>> {
        let mut wots = WinternitzOTSPlus::<32, 80>::new(16)?;
        
        // Need to generate keys since WinternitzOTSPlus::chain requires public_seed
        wots.generate_keys()?;
        
        let input = [0u8; 32];
        let mut output = [0u8; 32];
        let addr = 0;
        
        // Valid parameters
        let result = wots.chain(&input, 0, 15, addr, &mut output);
        assert!(result.is_ok());
        
        // Invalid start parameter
        let result = wots.chain(&input, 16, 1, addr, &mut output);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::InvalidChainParameters));
        }
        
        // Invalid steps parameter
        let result = wots.chain(&input, 10, 7, addr, &mut output);
        assert!(result.is_err());
        if let Err(err) = result {
            assert!(matches!(err, WotsError::InvalidChainParameters));
        }
        
        Ok(())
    }

    // Test different hash output sizes for WinternitzOTS
    #[test]
    fn test_winternitz_hash_sizes() -> Result<(), Box<dyn std::error::Error>> {
        // Test with N=16 (smaller than SHA-256 output)
        let mut wots_16 = WinternitzOTS::<16, 80>::new(16)?;
        wots_16.generate_keys()?;
        
        let message = b"Testing with N=16";
        let mut signature_16 = [[0u8; 16]; 80];
        wots_16.sign(message, &mut signature_16)?;
        
        let is_valid = wots_16.verify(message, &signature_16)?;
        assert!(is_valid);
        
        // Test with N=32 (same as SHA-256 output)
        let mut wots_32 = WinternitzOTS::<32, 80>::new(16)?;
        wots_32.generate_keys()?;
        
        let message = b"Testing with N=32";
        let mut signature_32 = [[0u8; 32]; 80];
        wots_32.sign(message, &mut signature_32)?;
        
        let is_valid = wots_32.verify(message, &signature_32)?;
        assert!(is_valid);
        
        // Test with N=24 (arbitrary size smaller than SHA-256 output)
        let mut wots_24 = WinternitzOTS::<24, 80>::new(16)?;
        wots_24.generate_keys()?;
        
        let message = b"Testing with N=24";
        let mut signature_24 = [[0u8; 24]; 80];
        wots_24.sign(message, &mut signature_24)?;
        
        let is_valid = wots_24.verify(message, &signature_24)?;
        assert!(is_valid);
        
        Ok(())
    }
    
    // Test different hash output sizes for WinternitzOTSPlus
    #[test]
    fn test_winternitz_plus_hash_sizes() -> Result<(), Box<dyn std::error::Error>> {
        // Test with N=16 (smaller than SHA-256 output)
        let mut wots_16 = WinternitzOTSPlus::<16, 80>::new(16)?;
        wots_16.generate_keys()?;
        
        let message = b"Testing with N=16";
        let mut signature_16 = [[0u8; 16]; 80];
        wots_16.sign(message, &mut signature_16)?;
        
        let is_valid = wots_16.verify(message, &signature_16)?;
        assert!(is_valid);
        
        // Test with N=32 (same as SHA-256 output)
        let mut wots_32 = WinternitzOTSPlus::<32, 80>::new(16)?;
        wots_32.generate_keys()?;
        
        let message = b"Testing with N=32";
        let mut signature_32 = [[0u8; 32]; 80];
        wots_32.sign(message, &mut signature_32)?;
        
        let is_valid = wots_32.verify(message, &signature_32)?;
        assert!(is_valid);
        
        // Test with N=24 (arbitrary size smaller than SHA-256 output)
        let mut wots_24 = WinternitzOTSPlus::<24, 80>::new(16)?;
        wots_24.generate_keys()?;
        
        let message = b"Testing with N=24";
        let mut signature_24 = [[0u8; 24]; 80];
        wots_24.sign(message, &mut signature_24)?;
        
        let is_valid = wots_24.verify(message, &signature_24)?;
        assert!(is_valid);
        
        Ok(())
    }
}