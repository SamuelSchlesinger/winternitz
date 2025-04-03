use sha2::{Sha256, Digest};
use rand::{RngCore, rngs::OsRng};
use std::fmt;

#[derive(Debug)]
pub enum WotsError {
    InvalidWinternitzParameter,
    KeysNotGenerated,
    InvalidSignature,
    InvalidChainParameters,
    Verification,
}

impl fmt::Display for WotsError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            WotsError::InvalidWinternitzParameter => write!(f, "Winternitz parameter must be a power of 2"),
            WotsError::KeysNotGenerated => write!(f, "Keys not generated. Call generate_keys() first"),
            WotsError::InvalidSignature => write!(f, "Invalid signature length"),
            WotsError::InvalidChainParameters => write!(f, "Invalid chain parameters"),
            WotsError::Verification => write!(f, "Signature verification failed"),
        }
    }
}

impl std::error::Error for WotsError {}

pub struct WinternitzOTS {
    w: u32,           // Winternitz parameter (must be a power of 2)
    n: usize,         // Security parameter (hash output length in bytes)
    log_w: u32,       // Log base 2 of w
    len_1: usize,     // Number of w-bit blocks for message digest
    len_2: usize,     // Number of w-bit blocks for checksum
    len: usize,       // Total number of blocks (len_1 + len_2)
    private_key: Option<Vec<Vec<u8>>>,
    public_key: Option<Vec<Vec<u8>>>,
}

impl WinternitzOTS {
    /// Create a new Winternitz One-Time Signature instance
    pub fn new(w: u32, n: usize) -> Result<Self, WotsError> {
        // Check if w is a power of 2
        if w < 2 || (w & (w - 1)) != 0 {
            return Err(WotsError::InvalidWinternitzParameter);
        }
        
        // Calculate derived parameters
        let log_w = w.trailing_zeros();
        
        // Number of w-bit blocks needed to represent n-byte message digest
        let len_1 = ((8 * n) as f64 / log_w as f64).ceil() as usize;
        
        // Number of w-bit blocks needed for checksum
        let len_2 = ((((len_1 * (w as usize - 1)) as f64).log2() / log_w as f64).floor() as usize) + 1;
        
        // Total number of blocks
        let len = len_1 + len_2;
        
        Ok(WinternitzOTS {
            w,
            n,
            log_w,
            len_1,
            len_2,
            len,
            private_key: None,
            public_key: None,
        })
    }
    
    /// Hash function using SHA-256
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()[..self.n].to_vec()
    }
    
    /// Apply the hash chain function
    fn chain(&self, x: &[u8], start: u32, steps: u32) -> Result<Vec<u8>, WotsError> {
        if start >= self.w || steps > (self.w - start) {
            return Err(WotsError::InvalidChainParameters);
        }
        
        let mut result = x.to_vec();
        for i in start..(start + steps) {
            // Prepend chain index to prevent potential multi-target attacks
            let mut data = Vec::with_capacity(2 + result.len());
            data.extend_from_slice(&(i as u16).to_be_bytes());
            data.extend_from_slice(&result);
            result = self.hash(&data);
        }
        
        Ok(result)
    }
    
    /// Generate a new private-public key pair
    pub fn generate_keys(&mut self) -> Result<(), WotsError> {
        // Generate private key: len random n-byte values
        let mut private_key = Vec::with_capacity(self.len);
        
        for _ in 0..self.len {
            let mut key = vec![0u8; self.n];
            OsRng.fill_bytes(&mut key);
            private_key.push(key);
        }
        
        // Generate public key: apply hash chain w-1 times to each private key element
        let mut public_key = Vec::with_capacity(self.len);
        
        for i in 0..self.len {
            let pk = self.chain(&private_key[i], 0, self.w - 1)?;
            public_key.push(pk);
        }
        
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        
        Ok(())
    }
    
    /// Convert message digest to base w representation
    fn convert_to_base_w(&self, msg_digest: &[u8]) -> Vec<u32> {
        let bits_per_digit = self.log_w as usize;
        let mut result = Vec::with_capacity(self.len_1);
        
        // Process each byte of the message digest
        for byte in msg_digest {
            let mut bits_remaining = 8;
            let byte_value = *byte;
            
            while bits_remaining >= bits_per_digit {
                bits_remaining -= bits_per_digit;
                // Extract bits_per_digit bits and convert to integer
                let digit = (byte_value >> bits_remaining) & (self.w - 1) as u8;
                result.push(digit as u32);
            }
        }
        
        // If we need more digits, add them (padding)
        while result.len() < self.len_1 {
            result.push(0);
        }
        
        // Truncate if we got too many
        result.truncate(self.len_1);
        result
    }
    
    /// Compute checksum for the base w message representation
    fn compute_checksum(&self, msg_base_w: &[u32]) -> Vec<u32> {
        // Compute checksum (sum of w-1 - digit for each digit)
        let checksum: u32 = msg_base_w.iter()
            .map(|&d| (self.w - 1) - d)
            .sum();
        
        // Convert checksum to base w representation
        let mut checksum_base_w = Vec::with_capacity(self.len_2);
        let mut remaining_checksum = checksum;
        
        while remaining_checksum > 0 || checksum_base_w.len() < self.len_2 {
            checksum_base_w.push(remaining_checksum % self.w);
            remaining_checksum /= self.w;
        }
        
        // Pad to len_2
        while checksum_base_w.len() < self.len_2 {
            checksum_base_w.push(0);
        }
        
        // Truncate if we got too many
        checksum_base_w.truncate(self.len_2);
        checksum_base_w
    }
    
    /// Sign a message using the Winternitz one-time signature scheme
    pub fn sign(&self, message: &[u8]) -> Result<Vec<Vec<u8>>, WotsError> {
        let private_key = match &self.private_key {
            Some(key) => key,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        // Hash the message
        let msg_digest = self.hash(message);
        
        // Convert to base w representation
        let msg_base_w = self.convert_to_base_w(&msg_digest);
        
        // Compute checksum and convert to base w
        let checksum_base_w = self.compute_checksum(&msg_base_w);
        
        // Combine message and checksum digits
        let mut combined = Vec::with_capacity(self.len);
        combined.extend_from_slice(&msg_base_w);
        combined.extend_from_slice(&checksum_base_w);
        
        // Generate signature: for each digit, apply hash chain 'digit' times
        let mut signature = Vec::with_capacity(self.len);
        
        for i in 0..self.len {
            let sig = self.chain(&private_key[i], 0, combined[i])?;
            signature.push(sig);
        }
        
        Ok(signature)
    }
    
    /// Verify a Winternitz one-time signature
    pub fn verify(&self, message: &[u8], signature: &[Vec<u8>]) -> Result<bool, WotsError> {
        let public_key = match &self.public_key {
            Some(key) => key,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        if signature.len() != self.len {
            return Err(WotsError::InvalidSignature);
        }
        
        // Hash the message
        let msg_digest = self.hash(message);
        
        // Convert to base w representation
        let msg_base_w = self.convert_to_base_w(&msg_digest);
        
        // Compute checksum and convert to base w
        let checksum_base_w = self.compute_checksum(&msg_base_w);
        
        // Combine message and checksum digits
        let mut combined = Vec::with_capacity(self.len);
        combined.extend_from_slice(&msg_base_w);
        combined.extend_from_slice(&checksum_base_w);
        
        // Verify signature: for each digit, complete the hash chain to w-1 steps
        let mut computed_public_key = Vec::with_capacity(self.len);
        
        for i in 0..self.len {
            let pk = self.chain(&signature[i], combined[i], self.w - 1 - combined[i])?;
            computed_public_key.push(pk);
        }
        
        // Check if computed public key matches the actual public key
        Ok(computed_public_key == *public_key)
    }
    
    /// Get the public key
    pub fn get_public_key(&self) -> Result<&Vec<Vec<u8>>, WotsError> {
        match &self.public_key {
            Some(key) => Ok(key),
            None => Err(WotsError::KeysNotGenerated),
        }
    }
}

/// Enhanced Winternitz One-Time Signature Plus (WOTS+) implementation
pub struct WinternitzOTSPlus {
    w: u32,           // Winternitz parameter (must be a power of 2)
    n: usize,         // Security parameter (hash output length in bytes)
    log_w: u32,       // Log base 2 of w
    len_1: usize,     // Number of w-bit blocks for message digest
    len_2: usize,     // Number of w-bit blocks for checksum
    len: usize,       // Total number of blocks (len_1 + len_2)
    private_key: Option<Vec<Vec<u8>>>,
    public_key: Option<Vec<Vec<u8>>>,
    public_seed: Option<Vec<u8>>,
    address_space: Option<Vec<Vec<u8>>>,
}

impl WinternitzOTSPlus {
    /// Create a new Winternitz One-Time Signature Plus instance
    pub fn new(w: u32, n: usize) -> Result<Self, WotsError> {
        // Check if w is a power of 2
        if w < 2 || (w & (w - 1)) != 0 {
            return Err(WotsError::InvalidWinternitzParameter);
        }
        
        // Calculate derived parameters
        let log_w = w.trailing_zeros();
        
        // Number of w-bit blocks needed to represent n-byte message digest
        let len_1 = ((8 * n) as f64 / log_w as f64).ceil() as usize;
        
        // Number of w-bit blocks needed for checksum
        let len_2 = ((((len_1 * (w as usize - 1)) as f64).log2() / log_w as f64).floor() as usize) + 1;
        
        // Total number of blocks
        let len = len_1 + len_2;
        
        Ok(WinternitzOTSPlus {
            w,
            n,
            log_w,
            len_1,
            len_2,
            len,
            private_key: None,
            public_key: None,
            public_seed: None,
            address_space: None,
        })
    }
    
    /// Hash function using SHA-256
    fn hash(&self, data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.finalize()[..self.n].to_vec()
    }
    
    /// Pseudorandom function for key generation
    fn prf(&self, key: &[u8], addr: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(key);
        hasher.update(addr);
        hasher.finalize()[..self.n].to_vec()
    }
    
    /// Keyed hash function for the WOTS+ chain
    fn hash_with_seed(&self, public_seed: &[u8], addr: &[u8], data: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(public_seed);
        hasher.update(addr);
        hasher.update(data);
        hasher.finalize()[..self.n].to_vec()
    }
    
    /// Apply the hash chain function for WOTS+
    fn chain(&self, x: &[u8], start: u32, steps: u32, addr: &[u8]) -> Result<Vec<u8>, WotsError> {
        if start >= self.w || steps > (self.w - start) {
            return Err(WotsError::InvalidChainParameters);
        }
        
        let public_seed = match &self.public_seed {
            Some(seed) => seed,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        let mut result = x.to_vec();
        for i in start..(start + steps) {
            // Create a unique address for this chain position
            let mut chain_addr = addr.to_vec();
            chain_addr.extend_from_slice(&(i as u16).to_be_bytes());
            
            // Apply the keyed hash function
            result = self.hash_with_seed(public_seed, &chain_addr, &result);
        }
        
        Ok(result)
    }
    
    /// Generate a new private-public key pair for WOTS+
    pub fn generate_keys(&mut self) -> Result<(), WotsError> {
        // Generate public seed for randomization
        let mut public_seed = vec![0u8; self.n];
        OsRng.fill_bytes(&mut public_seed);
        self.public_seed = Some(public_seed);
        
        // Generate address space (one address per hash chain)
        let mut address_space = Vec::with_capacity(self.len);
        for i in 0..self.len {
            let addr = (i as u32).to_be_bytes().to_vec();
            address_space.push(addr);
        }
        self.address_space = Some(address_space);
        
        // Generate secret seed
        let mut secret_seed = vec![0u8; self.n];
        OsRng.fill_bytes(&mut secret_seed);
        
        // Generate private key
        let address_space = self.address_space.as_ref().unwrap();
        let mut private_key = Vec::with_capacity(self.len);
        
        for i in 0..self.len {
            let key = self.prf(&secret_seed, &address_space[i]);
            private_key.push(key);
        }
        
        // Generate public key: apply hash chain w-1 times to each private key element
        let mut public_key = Vec::with_capacity(self.len);
        
        for i in 0..self.len {
            let pk = self.chain(&private_key[i], 0, self.w - 1, &address_space[i])?;
            public_key.push(pk);
        }
        
        self.private_key = Some(private_key);
        self.public_key = Some(public_key);
        
        Ok(())
    }
    
    /// Convert message digest to base w representation
    fn convert_to_base_w(&self, msg_digest: &[u8]) -> Vec<u32> {
        let bits_per_digit = self.log_w as usize;
        let mut result = Vec::with_capacity(self.len_1);
        
        // Process each byte of the message digest
        for byte in msg_digest {
            let mut bits_remaining = 8;
            let byte_value = *byte;
            
            while bits_remaining >= bits_per_digit {
                bits_remaining -= bits_per_digit;
                // Extract bits_per_digit bits and convert to integer
                let digit = (byte_value >> bits_remaining) & (self.w - 1) as u8;
                result.push(digit as u32);
            }
        }
        
        // If we need more digits, add them (padding)
        while result.len() < self.len_1 {
            result.push(0);
        }
        
        // Truncate if we got too many
        result.truncate(self.len_1);
        result
    }
    
    /// Compute checksum for the base w message representation
    fn compute_checksum(&self, msg_base_w: &[u32]) -> Vec<u32> {
        // Compute checksum (sum of w-1 - digit for each digit)
        let checksum: u32 = msg_base_w.iter()
            .map(|&d| (self.w - 1) - d)
            .sum();
        
        // Convert checksum to base w representation
        let mut checksum_base_w = Vec::with_capacity(self.len_2);
        let mut remaining_checksum = checksum;
        
        while remaining_checksum > 0 || checksum_base_w.len() < self.len_2 {
            checksum_base_w.push(remaining_checksum % self.w);
            remaining_checksum /= self.w;
        }
        
        // Pad to len_2
        while checksum_base_w.len() < self.len_2 {
            checksum_base_w.push(0);
        }
        
        // Truncate if we got too many
        checksum_base_w.truncate(self.len_2);
        checksum_base_w
    }
    
    /// Sign a message using the Winternitz one-time signature plus scheme
    pub fn sign(&self, message: &[u8]) -> Result<Vec<Vec<u8>>, WotsError> {
        let private_key = match &self.private_key {
            Some(key) => key,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        let address_space = match &self.address_space {
            Some(addr) => addr,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        // Hash the message
        let msg_digest = self.hash(message);
        
        // Convert to base w representation
        let msg_base_w = self.convert_to_base_w(&msg_digest);
        
        // Compute checksum and convert to base w
        let checksum_base_w = self.compute_checksum(&msg_base_w);
        
        // Combine message and checksum digits
        let mut combined = Vec::with_capacity(self.len);
        combined.extend_from_slice(&msg_base_w);
        combined.extend_from_slice(&checksum_base_w);
        
        // Generate signature: for each digit, apply hash chain 'digit' times
        let mut signature = Vec::with_capacity(self.len);
        
        for i in 0..self.len {
            let sig = self.chain(&private_key[i], 0, combined[i], &address_space[i])?;
            signature.push(sig);
        }
        
        Ok(signature)
    }
    
    /// Verify a Winternitz one-time signature plus
    pub fn verify(&self, message: &[u8], signature: &[Vec<u8>]) -> Result<bool, WotsError> {
        let public_key = match &self.public_key {
            Some(key) => key,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        let address_space = match &self.address_space {
            Some(addr) => addr,
            None => return Err(WotsError::KeysNotGenerated),
        };
        
        if signature.len() != self.len {
            return Err(WotsError::InvalidSignature);
        }
        
        // Hash the message
        let msg_digest = self.hash(message);
        
        // Convert to base w representation
        let msg_base_w = self.convert_to_base_w(&msg_digest);
        
        // Compute checksum and convert to base w
        let checksum_base_w = self.compute_checksum(&msg_base_w);
        
        // Combine message and checksum digits
        let mut combined = Vec::with_capacity(self.len);
        combined.extend_from_slice(&msg_base_w);
        combined.extend_from_slice(&checksum_base_w);
        
        // Verify signature: for each digit, complete the hash chain to w-1 steps
        let mut computed_public_key = Vec::with_capacity(self.len);
        
        for i in 0..self.len {
            let pk = self.chain(&signature[i], combined[i], self.w - 1 - combined[i], &address_space[i])?;
            computed_public_key.push(pk);
        }
        
        // Check if computed public key matches the actual public key
        Ok(computed_public_key == *public_key)
    }
    
    /// Get the public key
    pub fn get_public_key(&self) -> Result<&Vec<Vec<u8>>, WotsError> {
        match &self.public_key {
            Some(key) => Ok(key),
            None => Err(WotsError::KeysNotGenerated),
        }
    }
    
    /// Get the public seed
    pub fn get_public_seed(&self) -> Result<&Vec<u8>, WotsError> {
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
        let mut wots = WinternitzOTS::new(16, 32)?;
        
        // Generate keys
        wots.generate_keys()?;
        
        // Message to sign
        let message = b"This is a test message to be signed with Winternitz OTS";
        
        // Sign the message
        let signature = wots.sign(message)?;
        
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
        let mut wots_plus = WinternitzOTSPlus::new(16, 32)?;
        
        // Generate keys
        wots_plus.generate_keys()?;
        
        // Message to sign
        let message = b"This is a test message to be signed with Winternitz OTS";
        
        // Sign the message
        let signature_plus = wots_plus.sign(message)?;
        
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
