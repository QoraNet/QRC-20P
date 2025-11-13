//! BN256-specific Poseidon spec for halo2_gadgets
//!
//! Since P128Pow5T3 only works with Pasta curves, we need a custom spec for BN256

use crate::common_types::Fr;
use ff::PrimeField;
use once_cell::sync::Lazy;

// Custom Spec trait for Poseidon since halo2-axiom doesn't have halo2_gadgets
pub trait Spec<F: PrimeField, const WIDTH: usize, const RATE: usize> {
    fn full_rounds() -> usize;
    fn partial_rounds() -> usize;
    fn sbox(val: F) -> F;
    fn constants() -> (Vec<[F; WIDTH]>, [[F; WIDTH]; WIDTH]);
}

type Mds<F, const WIDTH: usize> = [[F; WIDTH]; WIDTH];

/// Custom Poseidon specification for BN256 curve
#[derive(Clone, Copy, Debug)]
pub struct Bn256Spec<const WIDTH: usize, const RATE: usize>;

/// Generate constants for WIDTH=3 (called once and cached)
fn generate_constants_width3() -> (Vec<[Fr; 3]>, [[Fr; 3]; 3]) {
    use sha3::{Digest, Keccak256};

    let mut round_constants = Vec::new();
    let seed = b"Poseidon_constants_BN256_WIDTH_3_RATE_2";

    for round_idx in 0..65 {
        let mut round = [Fr::zero(); 3];
        for col_idx in 0..3 {
            let mut hasher = Keccak256::default();
            hasher.update(seed);
            hasher.update(&(round_idx as u32).to_le_bytes());
            hasher.update(&(col_idx as u32).to_le_bytes());
            hasher.update(b"_round_constant");

            let hash = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hash[..32]);
            bytes[31] &= 0x3f; // BN256 field is ~254 bits

            // ✅ FIX: Use from_repr() instead of from_bytes()
            round[col_idx] = Fr::from_repr(bytes)
                .unwrap_or_else(|| {
                    Fr::from(((round_idx + 1) * (col_idx + 1)) as u64)
                });
        }
        round_constants.push(round);
    }

    // Production MDS matrix for width 3 (Cauchy matrix)
    let x_values = [Fr::from(0), Fr::from(1), Fr::from(2)];
    let y_values = [Fr::from(3), Fr::from(4), Fr::from(5)];

    let mut mds = [[Fr::zero(); 3]; 3];
    for i in 0..3 {
        for j in 0..3 {
            let sum = x_values[i] + y_values[j];
            mds[i][j] = sum.invert().unwrap_or(Fr::from(1));
        }
    }

    (round_constants, mds)
}

/// Generate constants for WIDTH=2 (called once and cached)
fn generate_constants_width2() -> (Vec<[Fr; 2]>, [[Fr; 2]; 2]) {
    use sha3::{Digest, Keccak256};

    let mut round_constants = Vec::new();
    let seed = b"Poseidon_constants_BN256_WIDTH_2_RATE_1";

    for round_idx in 0..64 {
        let mut round = [Fr::zero(); 2];
        for col_idx in 0..2 {
            let mut hasher = Keccak256::default();
            hasher.update(seed);
            hasher.update(&(round_idx as u32).to_le_bytes());
            hasher.update(&(col_idx as u32).to_le_bytes());
            hasher.update(b"_round_constant");

            let hash = hasher.finalize();
            let mut bytes = [0u8; 32];
            bytes.copy_from_slice(&hash[..32]);
            bytes[31] &= 0x3f;

            // ✅ FIX: Use from_repr() instead of from_bytes()
            round[col_idx] = Fr::from_repr(bytes)
                .unwrap_or_else(|| {
                    Fr::from(((round_idx + 1) * (col_idx + 1)) as u64)
                });
        }
        round_constants.push(round);
    }

    // Production MDS matrix for width 2 (Cauchy matrix)
    let x_values = [Fr::from(0), Fr::from(1)];
    let y_values = [Fr::from(2), Fr::from(3)];

    let mut mds = [[Fr::zero(); 2]; 2];
    for i in 0..2 {
        for j in 0..2 {
            let sum = x_values[i] + y_values[j];
            mds[i][j] = sum.invert().unwrap_or(Fr::from(1));
        }
    }

    (round_constants, mds)
}

/// ✅ PERFORMANCE FIX: Cache constants (generated once on first use)
static CONSTANTS_WIDTH3: Lazy<(Vec<[Fr; 3]>, [[Fr; 3]; 3])> = Lazy::new(|| {
    generate_constants_width3()
});

/// ✅ PERFORMANCE FIX: Cache constants (generated once on first use)
static CONSTANTS_WIDTH2: Lazy<(Vec<[Fr; 2]>, [[Fr; 2]; 2])> = Lazy::new(|| {
    generate_constants_width2()
});

// Implementation for WIDTH=3, RATE=2 (for 2-to-1 hash)
impl Spec<Fr, 3, 2> for Bn256Spec<3, 2> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        57
    }

    fn sbox(val: Fr) -> Fr {
        // x^5 S-box
        val * val * val * val * val
    }

    fn constants() -> (Vec<[Fr; 3]>, Mds<Fr, 3>) {
        // ✅ PERFORMANCE FIX: Return cached constants (generated once on first call)
        // Avoids expensive Keccak256 hashing and field inversions on every Poseidon hash
        CONSTANTS_WIDTH3.clone()
    }
}

// Implementation for WIDTH=2, RATE=1
impl Spec<Fr, 2, 1> for Bn256Spec<2, 1> {
    fn full_rounds() -> usize {
        8
    }

    fn partial_rounds() -> usize {
        56
    }

    fn sbox(val: Fr) -> Fr {
        // x^5 S-box
        val * val * val * val * val
    }

    fn constants() -> (Vec<[Fr; 2]>, Mds<Fr, 2>) {
        // ✅ PERFORMANCE FIX: Return cached constants (generated once on first call)
        // Avoids expensive Keccak256 hashing and field inversions on every Poseidon hash
        CONSTANTS_WIDTH2.clone()
    }
}

// Type alias for convenience
pub type Bn256PoseidonSpec = Bn256Spec<3, 2>;
pub type Bn256PoseidonSpec2 = Bn256Spec<2, 1>;
