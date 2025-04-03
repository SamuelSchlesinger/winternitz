use sha2::{Sha256, Digest};
use rand::{RngCore, rngs::OsRng};
use std::fmt;

/// Maximum security parameter (hash output length in bytes)
pub const MAX_N: usize = 32;

/// Maximum length of chains for most practical use cases
pub const MAX_LEN: usize = 128;

#[derive(Debug)]
pub enum WotsError {
    InvalidWinternitzParameter,
    KeysNotGenerated,
    InvalidSignature,
    InvalidChainParameters,
    Verification,
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

/// Winternitz OTS with fixed-size arrays to avoid heap allocations
pub struct WinternitzOTS<const N: usize, const L: usize> {
    w: u32,                           // Winternitz parameter (must be a power of 2)
    log_w: u32,                       // Log base 2 of w
    len_1: usize,                     // Number of w-bit blocks for message digest
    len_2: usize,                     // Number of w-bit blocks for checksum
    len: usize,                       // Total number of blocks (len_1 + len_2)
    private_key: Option<[[u8; N]; L]>,
    public_key: Option<[[u8; N]; L]>,
}

impl<const N: usize, const L: usize> WinternitzOTS<N, L> {
    /// Create a new Winternitz One-Time Signature instance
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
    
    /// Hash function using SHA-256
    fn hash(&self, data: &[u8], output: &mut [u8; N]) {
        let mut hasher = Sha256::new();
        hasher.update(data);
        output.copy_from_slice(&hasher.finalize()[..N]);
    }
    
    /// Apply the hash chain function
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
    
    /// Generate a new private-public key pair
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
    
    /// Convert message digest to base w representation
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
    
    /// Compute checksum for the base w message representation
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
    
    /// Combines message base-w representation and checksum into a single array
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
    
    /// Sign a message using the Winternitz one-time signature scheme
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
    
    /// Verify a Winternitz one-time signature
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
    
    /// Get the public key
    pub fn get_public_key(&self) -> Result<&[[u8; N]; L], WotsError> {
        match &self.public_key {
            Some(key) => Ok(key),
            None => Err(WotsError::KeysNotGenerated),
        }
    }
}

/// Enhanced Winternitz One-Time Signature Plus (WOTS+) implementation with fixed-size arrays
pub struct WinternitzOTSPlus<const N: usize, const L: usize> {
    w: u32,                           // Winternitz parameter (must be a power of 2)
    log_w: u32,                       // Log base 2 of w
    len_1: usize,                     // Number of w-bit blocks for message digest
    len_2: usize,                     // Number of w-bit blocks for checksum
    len: usize,                       // Total number of blocks (len_1 + len_2)
    private_key: Option<[[u8; N]; L]>,
    public_key: Option<[[u8; N]; L]>,
    public_seed: Option<[u8; N]>,
    secret_seed: Option<[u8; N]>,
}

impl<const N: usize, const L: usize> WinternitzOTSPlus<N, L> {
    /// Create a new Winternitz One-Time Signature Plus instance
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
    
    /// Hash function using SHA-256
    fn hash(&self, data: &[u8], output: &mut [u8; N]) {
        let mut hasher = Sha256::new();
        hasher.update(data);
        output.copy_from_slice(&hasher.finalize()[..N]);
    }
    
    /// Pseudorandom function for key generation
    fn prf(&self, key: &[u8; N], addr: u32, output: &mut [u8; N]) {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(&addr.to_be_bytes());
        output.copy_from_slice(&hasher.finalize()[..N]);
    }
    
    /// Keyed hash function for the WOTS+ chain
    fn hash_with_seed(&self, public_seed: &[u8; N], addr: u32, chain_pos: u32, data: &[u8; N], output: &mut [u8; N]) {
        let mut hasher = Sha256::new();
        hasher.update(public_seed);
        hasher.update(&addr.to_be_bytes());
        hasher.update(&chain_pos.to_be_bytes());
        hasher.update(data);
        output.copy_from_slice(&hasher.finalize()[..N]);
    }
    
    /// Apply the hash chain function for WOTS+
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
    
    /// Generate a new private-public key pair for WOTS+
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
    
    /// Convert message digest to base w representation
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
    
    /// Compute checksum for the base w message representation
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
    
    /// Combines message base-w representation and checksum into a single array
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
    
    /// Sign a message using the Winternitz one-time signature plus scheme
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
    
    /// Verify a Winternitz one-time signature plus
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
    
    /// Get the public key
    pub fn get_public_key(&self) -> Result<&[[u8; N]; L], WotsError> {
        match &self.public_key {
            Some(key) => Ok(key),
            None => Err(WotsError::KeysNotGenerated),
        }
    }
    
    /// Get the public seed
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
}
