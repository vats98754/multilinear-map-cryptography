//! # Twist and Shout: zk-SNARK Memory Checking
//!
//! This library implements the Twist and Shout protocols for efficient zero-knowledge
//! memory checking in zkVMs and other applications requiring memory consistency proofs.
//!
//! ## Protocols
//!
//! - **Twist**: Read-write memory checking protocol that proves correct memory operations
//!   including reads, writes, and ordering constraints.
//! - **Shout**: Read-only lookup memory checking protocol optimized for static lookup tables.
//!
//! ## Features
//!
//! - Optimized prover performance with logarithmic verifier complexity
//! - Modular commitment scheme support (KZG by default)
//! - Comprehensive benchmarking against baseline implementations
//! - Ready for integration with zkVMs like Jolt
//!
//! ## Example
//!
//! ```rust
//! use twist_and_shout::{Twist, MemoryTrace, setup_params};
//!
//! // Set up parameters for memory size 2^10
//! let params = setup_params(10);
//!
//! // Create a memory trace
//! let mut trace = MemoryTrace::new(1024);
//! trace.write(0, 42);
//! trace.write(1, 73);
//! let val = trace.read(0);
//!
//! // Generate proof
//! let twist = Twist::new(&params);
//! let proof = twist.prove(&trace).unwrap();
//!
//! // Verify proof
//! assert!(twist.verify(&proof).unwrap());
//! ```

pub mod commitments;
pub mod polynomials;
pub mod sumcheck;
pub mod twist;
pub mod shout;
pub mod utils;
pub mod benchmarks;

// Re-export main types for convenience
pub use twist::{Twist, TwistProof, MemoryTrace, MemoryOp};
pub use shout::{Shout, ShoutProof, LookupTable, LookupOp};
pub use commitments::{CommitmentScheme, KZGCommitment};
pub use polynomials::MultilinearExtension;
pub use utils::FieldElement;
pub use utils::{setup_params, ProverParams, VerifierParams};

/// Common error types for the library
#[derive(Debug, thiserror::Error)]
pub enum TwistAndShoutError {
    #[error("Invalid parameters: {0}")]
    InvalidParameters(String),
    
    #[error("Proof generation failed: {0}")]
    ProofGeneration(String),
    
    #[error("Proof verification failed: {0}")]
    ProofVerification(String),
    
    #[error("Commitment error: {0}")]
    Commitment(String),
    
    #[error("Polynomial operation failed: {0}")]
    Polynomial(String),
    
    #[error("Sum-check protocol error: {0}")]
    SumCheck(String),
}

pub type Result<T> = std::result::Result<T, TwistAndShoutError>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_library_imports() {
        // Basic smoke test to ensure all modules compile
        let _ = setup_params(4);
    }
}