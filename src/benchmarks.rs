//! Benchmarking utilities for Twist and Shout protocols.

use crate::utils::{FieldElement, setup_params};

/// Simple benchmarking placeholder - will be expanded when protocols are complete
pub fn benchmark_setup(log_size: usize) -> (usize, usize) {
    let (prover_params, verifier_params) = setup_params(log_size);
    (prover_params.max_operations, verifier_params.max_operations)
}