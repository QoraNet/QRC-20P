//! Error types for privacy library

use thiserror::Error;

/// Privacy library errors
#[derive(Error, Debug, Clone)]
pub enum PrivacyError {
    #[error("Failed to initialize proof system: {0}")]
    ProofSystemInit(String),

    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),

    #[error("Proof verification failed: {0}")]
    ProofVerification(String),

    #[error("Invalid commitment: {0}")]
    InvalidCommitment(String),

    #[error("Invalid nullifier: {0}")]
    InvalidNullifier(String),

    #[error("Invalid Merkle proof: {0}")]
    InvalidMerkleProof(String),

    #[error("Merkle tree error: {0}")]
    MerkleTree(String),

    #[error("Stealth address error: {0}")]
    StealthAddress(String),

    #[error("Invalid amount: {0}")]
    InvalidAmount(String),

    #[error("Cryptographic error: {0}")]
    Cryptographic(String),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Invalid input: {0}")]
    InvalidInput(String),

    #[error("Circuit error: {0}")]
    Circuit(String),

    #[error("Parameter loading error: {0}")]
    ParameterLoad(String),
}

/// Alias for Result with PrivacyError
pub type PrivacyResult<T> = Result<T, PrivacyError>;
