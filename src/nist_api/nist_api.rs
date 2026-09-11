//! NIST RNG Wrapper Functions
//!
//! These functions wrap the public HQC-KEM API to add RNG-based seeding, matching the NIST PQC
//! submission format. They are used exclusively by KAT tests to validate against official test vectors.
//!
//! Note: These functions are intentionally kept private to the crate to maintain a clean public API.
//! Users should use the public functions (keygen, encaps, decaps) from the root module directly.

use crate::{decaps, encaps, keygen, HqcParams};

/// Seed size for NIST encapsulation (combines entropy and salt)
const SALT_SIZE: usize = 16;

/// Fixed shared secret size used in NIST API compliance
const SHARED_SECRET_SIZE: usize = 32;

/// NIST-compatible key generation with RNG seeding
///
/// Generates a random 32-byte seed from the provided RNG and passes it to the public keygen function.
/// Returns a tuple of (pk_size, sk_size).
pub(crate) fn nist_keygen<R: rand_core::RngCore>(
    param: &HqcParams,
    pk_out: &mut [u8],
    sk_out: &mut [u8],
    rng: &mut R,
) -> (usize, usize) {
    // Generate random seed for deterministic key generation
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    keygen(param, &seed, pk_out, sk_out)
}

/// NIST-compatible encapsulation with RNG seeding
///
/// Generates random seed material from RNG combining security parameter bytes and salt,
/// then passes to public encaps function. This matches NIST submission requirements.
pub(crate) fn nist_encaps<R: rand_core::RngCore>(
    param: &HqcParams,
    public_key: &[u8],
    shared_secret: &mut [u8],
    ciphertext: &mut [u8],
    rng: &mut R,
) {
    // Build seed: [entropy_bytes | salt_bytes] where entropy = security_bits/8
    let mut seed = [0u8; SALT_SIZE + SHARED_SECRET_SIZE];
    let security_bytes = param.security_bits / 8;
    rng.fill_bytes(&mut seed[..security_bytes]);
    rng.fill_bytes(&mut seed[security_bytes..security_bytes + SALT_SIZE]);
    encaps(param, &seed, public_key, shared_secret, ciphertext);
}

/// NIST-compatible decapsulation
///
/// Calls public decaps and ensures output is exactly SHARED_SECRET_SIZE bytes.
/// Used for KAT validation to confirm decapsulation produces expected shared secrets.
pub(crate) fn nist_decaps(p: &HqcParams, dk_kem: &[u8], ct: &[u8], shared_secret: &mut [u8]) {
    // Decapsulate into fixed-size buffer, then copy to output
    let mut ss = [0u8; SHARED_SECRET_SIZE];
    decaps(p, dk_kem, ct, &mut ss);
    shared_secret.copy_from_slice(&ss);
}
