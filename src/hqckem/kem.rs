// SPDX-License-Identifier: MIT
// SPDX-FileContributor: Kris Kwiatkowski

//! HQC (Hamming Quasi-Cyclic) - Rust Implementation
//!
//! This is an educational implementation of the HQC post-quantum key encapsulation mechanism (KEM)
//! based on the HQC specification from https://pqc-hqc.org/doc/hqc_specifications_2025_08_22.pdf
//!
//! HQC is a code-based cryptosystem that uses quasi-cyclic codes and is a candidate for
//! NIST post-quantum standardization. It provides three security levels: HQC-128, HQC-192, and HQC-256.
//!
//! The implementation includes:
//! - Key generation (PKE and KEM)
//! - Encryption/Encapsulation
//! - Decryption/Decapsulation
//! - Reed-Solomon and Reed-Muller error correction codes
//! - Galois field arithmetic (GF(256))
//! - Vector operations over GF(2)[X]/(X^n - 1)

use super::pke::*;
use crate::coders::common::*;
use crate::common::consts::*;
use crate::common::*;
use crate::field::*;

// ============================================================================
// HQC Parameter Set Structure
// ============================================================================

/// Runtime parameters for an HQC parameter set (HQC-128, HQC-192, or HQC-256).
/// These define the security level and operational characteristics of the scheme.
pub struct HqcParams {
    /// Parameter set name (e.g., "HQC-128", "HQC-192", "HQC-256")
    pub name: &'static str,
    /// Code length: n (dimension of the quasi-cyclic code)
    /// Code length: n (dimension of the quasi-cyclic code)
    pub n: usize,
    /// Reed-Solomon code parameter: n1 (codeword length in GF(256) symbols)
    pub n1: usize,
    /// Reed-Muller multiplicity: n2 (RM codeword length in bits)
    pub n2: usize,
    /// Message length: k (in bytes)
    pub k: usize,
    /// Reed-Solomon error correction capability: delta (can correct up to delta errors)
    pub delta: usize,
    /// Hamming weight of secret key vectors x, y
    pub omega: usize,
    /// Hamming weight of random vectors r1, r2 during encryption
    pub omega_r: usize,
    /// Hamming weight of error vector e during encryption
    pub omega_e: usize,
    /// Security level in bits (128, 192, or 256)
    pub security_bits: usize,
    /// Precomputed Barrett reduction parameter: μ = ⌊2^32 / n⌋
    pub n_mu: u64,
    /// Rejection threshold for fixed-weight sampling: ⌊2^24 / n⌋ * n
    pub threshold: u32,
    /// Reed-Solomon generator polynomial for this parameter set
    pub g_poly: &'static [u8],
}

impl HqcParams {
    /// Create an HQC parameter set by name.
    ///
    /// # Arguments
    /// * `name` - One of "HQC-128", "HQC-192", or "HQC-256"
    ///
    /// # Returns
    /// The corresponding parameter set, or an error if the name is invalid
    ///
    /// # Example
    /// ```
    /// use hqc::HqcParams;
    /// let params = HqcParams::new("HQC-128").unwrap();
    /// assert_eq!(params.name, "HQC-128");
    /// assert_eq!(params.security_bits, 128);
    /// ```
    pub fn new(name: &str) -> Result<Self, &'static str> {
        match name {
            // N=17669  n_size_bytes=2209  n1n2_size_bytes=2208
            // EK = 32 + 2209 = 2241   DK = 2241+32+16+32 = 2321   CT = 2209+2208+16 = 4433
            "HQC-128" => Ok(HqcParams {
                name: "HQC-128",
                n: 17669,
                n1: 46,
                n2: 384,
                k: 16,
                delta: 15,
                omega: 66,
                omega_r: 75,
                omega_e: 75,
                security_bits: 128,
                n_mu: 243079u64,
                threshold: 16767881u32,
                g_poly: G_POLY_128,
            }),

            // N=35851  n_size_bytes=4482  n1n2_size_bytes=4480
            // EK = 32 + 4482 = 4514   DK = 4514+32+24+32 = 4602   CT = 4482+4480+16 = 8978
            "HQC-192" => Ok(HqcParams {
                name: "HQC-192",
                n: 35851,
                n1: 56,
                n2: 640,
                k: 24,
                delta: 16,
                omega: 100,
                omega_r: 114,
                omega_e: 114,
                security_bits: 192,
                n_mu: 119800u64,
                threshold: 16742417u32,
                g_poly: G_POLY_192,
            }),

            // N=57637  n_size_bytes=7205  n1n2_size_bytes=7200
            // EK = 32 + 7205 = 7237   DK = 7237+32+32+32 = 7333   CT = 7205+7200+16 = 14421
            "HQC-256" => Ok(HqcParams {
                name: "HQC-256",
                n: 57637,
                n1: 90,
                n2: 640,
                k: 32, // this can be calculated
                delta: 29,
                omega: 131,
                omega_r: 149,
                omega_e: 149,
                security_bits: 256,
                n_mu: 74517u64,
                threshold: 16772367u32,
                g_poly: G_POLY_256,
            }),
            _ => todo!(),
        }
    }

    /// Returns security level in bytes (security_bits / 8)
    /// Returns security level in bytes (security_bits / 8)
    fn security_bytes(&self) -> usize {
        self.security_bits / 8
    }

    /// Returns the size of n-bit vectors in bytes: ⌈n/8⌉
    fn n_size_bytes(&self) -> usize {
        (self.n + 7) / 8
    }

    /// Returns the size of n-bit vectors in 64-bit words: ⌈n/64⌉
    fn n_size_64(&self) -> usize {
        (self.n + 63) / 64
    }

    /// Returns the size of (n1*n2)-bit vectors in bytes: ⌈(n1*n2)/8⌉
    fn n1n2_size_bytes(&self) -> usize {
        (self.n1 * self.n2 + 7) / 8
    }

    /// Returns the size of (n1*n2)-bit vectors in 64-bit words: ⌈(n1*n2)/64⌉
    fn n1n2_size_64(&self) -> usize {
        (self.n1 * self.n2 + 63) / 64
    }

    /// Returns public key size in bytes: n_size_bytes + 32 (for seed_ek)
    pub fn public_key_size(&self) -> usize {
        self.n_size_bytes() + 32 /* seed */
    }

    /// Returns secret key size in bytes
    pub fn secret_key_size(&self) -> usize {
        self.public_key_size() + 32 /* dk_pke */ + self.security_bytes() + 32 /* seed */
    }

    /// Returns shared secret size in bytes
    pub fn shared_secret_size(&self) -> usize {
        SHARED_SECRET_SIZE
    }

    /// Returns ciphertext size in bytes
    pub fn ciphertext_size(&self) -> usize {
        self.n_size_bytes() + self.n1n2_size_bytes() + SALT_SIZE
    }
}

// ============================================================================
// HQC Key Encapsulation Mechanism (KEM)
// ============================================================================
// The KEM uses the Fujisaki-Okamoto (FO) transform to convert the PKE into an IND-CCA2 secure KEM.

/// Generate HQC key pair from a seed.
///
/// # Arguments
/// * `p` - Parameter set (HQC-128, HQC-192, or HQC-256)
/// * `seed` - 32-byte random seed
/// * `pk_out` - Buffer for public key
/// * `sk_out` - Buffer for secret key
///
/// # Returns
/// Tuple of (public_key_size, secret_key_size)
/// HQC Key Generation
///
/// Generates a KEM key pair (public key and secret key) from a seed.
/// The seed should be random and at least 64 bytes for proper security.
///
/// # Arguments
/// * `p` - HQC parameter set (HQC-128, HQC-192, or HQC-256)
/// * `seed` - Random seed for key generation
/// * `pk_out` - Output buffer for public key (at least public_key_size() bytes)
/// * `sk_out` - Output buffer for secret key (at least dk_size() bytes)
///
/// # Returns
/// A tuple of (public_key_length, secret_key_length) in bytes
///
/// # Example
/// ```
/// use hqc::HqcParams;
/// let params = HqcParams::new("HQC-128").unwrap();
/// let seed = [0x42u8; 32];
/// // HQC-128: ek=2241 bytes, sk=2321 bytes
/// let mut pk = vec![0u8; 2241];
/// let mut sk = vec![0u8; 2321];
/// let (pk_len, sk_len) = hqc::keygen(&params, &seed, &mut pk, &mut sk);
/// assert_eq!(pk_len, 2241);
/// assert_eq!(sk_len, 2321);
/// ```
pub fn keygen(p: &HqcParams, seed: &[u8], pk_out: &mut [u8], sk_out: &mut [u8]) -> (usize, usize) {
    let mut ctx = xof_reader(&seed);
    let mut seed_pke: [u8; 32] = [0u8; 32];
    let mut sigma: [u8; 32] = [0u8; 32];
    ctx.read(&mut seed_pke);
    ctx.read(&mut sigma[..p.security_bytes()]);

    let mut dk: [u8; 32] = [0u8; 32];

    pke_keygen(
        &mut dk,
        pk_out,
        &seed_pke,
        p.n,
        p.n_size_bytes(),
        p.n_size_64(),
        p.omega,
        p.n_mu,
        p.threshold,
    );

    // Copy out secret key: [ek_pke | dk_pke | sigma | seed]
    let mut t = &mut sk_out[..];
    t = append_bytes(t, &pk_out[..p.public_key_size()]);
    t = append_bytes(t, &dk);
    t = append_bytes(t, &sigma[..p.security_bytes()]);
    _ = append_bytes(t, &seed);

    (
        p.public_key_size(),
        p.public_key_size() + 32 /*dk_pke*/ + p.security_bytes() + seed.len(),
    )
}

/// KEM encapsulation: generate a shared secret and ciphertext.
///
/// Uses the FO transform:
/// 1. Hash public key: hash_ek = H(pk)
/// 2. Derive K, theta from seed: (K || theta) = G(hash_ek || m || salt)
/// 3. Encrypt m: ct = PKE.Encrypt(pk, m; theta)
/// 4. Output (K, ct)
///
/// # Arguments
/// * `p` - Parameter set
/// * `seed` - Random seed: [m (security_bytes)] || [salt (16 bytes)]
/// * `public_key` - Recipient's public key
/// * `shared_secret` - Output buffer for 32-byte shared secret
/// * `ciphertext` - Output buffer for ciphertext
///
/// # Returns
/// Tuple of (shared_secret_size, ciphertext_size)
/// HQC Encapsulation
///
/// Encapsulates a shared secret under a public key.
/// Takes a seed (containing message and randomness) and derives a shared secret and ciphertext.
/// The seed should be at least 64 bytes (32 bytes message + 32 bytes randomness).
///
/// # Arguments
/// * `p` - HQC parameter set
/// * `seed` - Seed bytes (message || randomness)
/// * `public_key` - Public key from keygen
/// * `shared_secret` - Output buffer for shared secret (32 bytes)
/// * `ciphertext` - Output buffer for ciphertext (at least ct_size() bytes)
///
/// # Returns
/// A tuple of (shared_secret_length, ciphertext_length) in bytes
///
/// # Example
/// ```
/// use hqc::HqcParams;
/// let params = HqcParams::new("HQC-128").unwrap();
/// let seed = [0x55u8; 64];
/// // HQC-128: ek=2241 bytes, ct=4433 bytes
/// let pk = vec![0u8; 2241];
/// let mut ss = [0u8; 32];
/// let mut ct = vec![0u8; 4433];
/// let (ss_len, ct_len) = hqc::encaps(&params, &seed, &pk, &mut ss, &mut ct);
/// assert_eq!(ss_len, 32);
/// assert_eq!(ct_len, 4433);
/// ```
pub fn encaps(
    p: &HqcParams,
    seed: &[u8],
    public_key: &[u8],
    shared_secret: &mut [u8],
    ciphertext: &mut [u8],
) -> (usize, usize) {
    let (m, r) = seed.split_at(p.security_bytes());
    let (salt, _) = r.split_at(SALT_SIZE);

    let hash_ek = hash_h(public_key);
    let k_theta = hash_g(&hash_ek, &m, &salt);

    let mut u: [u64; MAX_N64] = [0u64; MAX_N64];
    let mut v: [u64; MAX_N1N2_64] = [0u64; MAX_N1N2_64];

    pke_encrypt(
        &mut u,
        &mut v,
        public_key,
        &m,
        &k_theta[SHARED_SECRET_SIZE..],
        p.n,
        p.n_size_bytes(),
        p.n_size_64(),
        p.n1,
        p.n2,
        p.k,
        p.omega_r,
        p.omega_e,
        p.n1n2_size_64(),
        p.g_poly,
    );

    let mut out = &mut ciphertext[..];
    out = append_vec_bytes(out, &u, p.n_size_bytes());
    out = append_vec_bytes(out, &v, p.n1n2_size_bytes());
    append_bytes(out, salt);

    let mut u_bytes: [u8; MAX_N64] = [0u8; MAX_N64];
    let mut v_bytes: [u8; MAX_N1N2_64] = [0u8; MAX_N1N2_64];
    vec_to_bytes_into(&u, &mut u_bytes);
    vec_to_bytes_into(&v, &mut v_bytes);

    shared_secret.copy_from_slice(&k_theta[..SHARED_SECRET_SIZE]);
    (
        shared_secret.len(),
        p.n_size_bytes() + p.n1n2_size_bytes() + SALT_SIZE,
    )
}

/// KEM decapsulation: recover shared secret from ciphertext.
///
/// Uses FO transform with implicit rejection:
/// 1. Decrypt ciphertext: m' = PKE.Decrypt(sk, ct)
/// 2. Derive K', theta': (K' || theta') = G(H(pk) || m' || salt)
/// 3. Re-encrypt: ct' = PKE.Encrypt(pk, m'; theta')
/// 4. If ct == ct': return K' (success)
///    Else: return K_bar = J(H(pk) || sigma || ct || salt) (implicit rejection)
///
/// Constant-time: both paths are computed, result selected via masking.
/// HQC Decapsulation
///
/// Decapsulates a shared secret from a ciphertext using the secret key.
/// Recovers the shared secret that was encapsulated under the corresponding public key.
///
/// # Arguments
/// * `p` - HQC parameter set
/// * `dk_kem` - Secret key from keygen
/// * `ct` - Ciphertext from encaps
/// * `shared_secret` - Output buffer for recovered shared secret (32 bytes)
///
/// # Example
/// ```
/// use hqc::HqcParams;
/// let params = HqcParams::new("HQC-128").unwrap();
/// // HQC-128: sk=2321 bytes, ct=4433 bytes
/// let dk = vec![0u8; 2321];
/// let ct = vec![0u8; 4433];
/// let mut ss = [0u8; 32];
/// hqc::decaps(&params, &dk, &ct, &mut ss);
/// ```
pub fn decaps(p: &HqcParams, dk_kem: &[u8], ct: &[u8], shared_secret: &mut [u8]) {
    let ek_pke = &dk_kem[..p.public_key_size()];
    let dk_pke = &dk_kem[p.public_key_size()..p.public_key_size() + 32];
    let sigma = &dk_kem[p.public_key_size() + 32..p.public_key_size() + 32 + 16];

    let u_bytes = &ct[..p.n_size_bytes()];
    let v_bytes = &ct[p.n_size_bytes()..p.n_size_bytes() + p.n1n2_size_bytes()];
    let salt = &ct[p.n_size_bytes() + p.n1n2_size_bytes()
        ..p.n_size_bytes() + p.n1n2_size_bytes() + SALT_SIZE];

    let mut u: [u64; MAX_N64] = [0u64; MAX_N64];
    let mut v: [u64; MAX_N1N2_64] = [0u64; MAX_N1N2_64];

    bytes_to_vec(&mut u, u_bytes);
    bytes_to_vec(&mut v, v_bytes);

    let mut m_prime = [0u8; MAX_K];
    pke_decrypt(
        &mut m_prime,
        &u,
        &v,
        dk_pke,
        p.n,
        p.n1,
        p.n2,
        p.k,
        p.delta,
        p.omega,
        p.n_mu,
        p.threshold,
        p.n1n2_size_64(),
    );
    // Shadow m_prime, so that it's used correctly
    let m_prime = &m_prime[..p.k];

    let hash_ek = hash_h(ek_pke);
    let k_theta_prime = hash_g(&hash_ek, m_prime, salt);
    let k_prime = &k_theta_prime[..32];
    let theta_prime = &k_theta_prime[32..];
    let mut u: [u64; MAX_N64] = [0u64; MAX_N64];
    let mut v: [u64; MAX_N1N2_64] = [0u64; MAX_N1N2_64];

    pke_encrypt(
        &mut u,
        &mut v,
        ek_pke,
        m_prime,
        theta_prime,
        p.n,
        p.n_size_bytes(),
        p.n_size_64(),
        p.n1,
        p.n2,
        p.k,
        p.omega_r,
        p.omega_e,
        p.n1n2_size_64(),
        p.g_poly,
    );

    let mut u_prime_bytes: [u8; MAX_N_BYTES] = [0u8; MAX_N_BYTES];
    vec_to_bytes(&mut u_prime_bytes, &u, p.n_size_bytes());
    let mut v_prime_bytes: [u8; MAX_N1N2_BYTES] = [0u8; MAX_N1N2_BYTES];
    vec_to_bytes(&mut v_prime_bytes, &v, p.n1n2_size_bytes());
    let k_bar = hash_j(&hash_ek, sigma, u_bytes, v_bytes, salt);

    let mut result: u8 = 0;
    result |= compare(u_bytes, &u_prime_bytes);
    result |= compare(v_bytes, &v_prime_bytes);
    result = result.wrapping_sub(1); // 0xFF on match, 0x00 on mismatch

    for i in 0..SHARED_SECRET_SIZE {
        shared_secret[i] = (k_prime[i] & result) ^ (k_bar[i] & !result);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_hqc128_kem() {
        let p: HqcParams = HqcParams::new("HQC-128").expect("Invalid parameter set name");
        let seed_keygen: [u8; 32] = [0u8; 32];
        let seed_encaps: [u8; 16 + 16] = [0u8; 16 + 16];
        let mut ek: [u8; 2241] = [0u8; 2241];
        let mut dk: [u8; 2321] = [0u8; 2321];
        let mut ct: [u8; 4433] = [0u8; 4433];
        let mut ss1: [u8; 32] = [0u8; 32];
        let mut ss2: [u8; 32] = [0u8; 32];
        // Key generation
        keygen(&p, &seed_keygen, &mut ek, &mut dk);
        // Encapsulation
        encaps(&p, &seed_encaps, &ek, &mut ss1, &mut ct);
        // Decapsulation
        decaps(&p, &dk, &ct, &mut ss2);
        assert_eq!(ss1, ss2);
    }

    #[test]
    fn test_hqc192_kem() {
        let p: HqcParams = HqcParams::new("HQC-192").expect("Invalid parameter set name");
        let seed_keygen: [u8; 32] = [0u8; 32];
        let seed_encaps: [u8; 24 + 16] = [0u8; 24 + 16];
        let mut ek: [u8; 4514] = [0u8; 4514];
        let mut dk: [u8; 4602] = [0u8; 4602];
        let mut ct: [u8; 8978] = [0u8; 8978];
        let mut ss1: [u8; 32] = [0u8; 32];
        let mut ss2: [u8; 32] = [0u8; 32];

        // Key generation
        keygen(&p, &seed_keygen, &mut ek, &mut dk);
        // Encapsulation
        encaps(&p, &seed_encaps, &ek, &mut ss1, &mut ct);
        // Decapsulation
        decaps(&p, &dk, &ct, &mut ss2);
        assert_eq!(ss1, ss2);
    }
    #[test]
    fn test_hqc256_kem() {
        let p: HqcParams = HqcParams::new("HQC-256").expect("Invalid parameter set name");
        let seed_keygen: [u8; 32] = [0u8; 32];
        let seed_encaps: [u8; 32 + 16] = [0u8; 32 + 16];
        let mut ek: [u8; 7237] = [0u8; 7237];
        let mut dk: [u8; 7333] = [0u8; 7333];
        let mut ct: [u8; 14_421] = [0u8; 14_421];
        let mut ss1: [u8; 32] = [0u8; 32];
        let mut ss2: [u8; 32] = [0u8; 32];

        // Key generation
        keygen(&p, &seed_keygen, &mut ek, &mut dk);
        // Encapsulation
        encaps(&p, &seed_encaps, &ek, &mut ss1, &mut ct);
        // Decapsulation
        decaps(&p, &dk, &ct, &mut ss2);
        assert_eq!(ss1, ss2);
    }
}
