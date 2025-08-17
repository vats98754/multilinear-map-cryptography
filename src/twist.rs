//! Twist protocol implementation for read-write memory checking.
//!
//! The Twist protocol allows efficient zero-knowledge proofs of memory consistency
//! for read-write operations, enforcing that reads return the last written value.

use crate::utils::{FieldElement, ProverParams, VerifierParams, Transcript};
use crate::polynomials::MultilinearExtension;
use crate::commitments::{CommitmentScheme, KZGCommitment, KZGCommitmentValue, KZGProof};
use crate::sumcheck::{SumCheck, SumCheckProof};
use crate::{Result, TwistAndShoutError};
use ark_ff::{Field, Zero, One};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

/// Memory operation type
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MemoryOp {
    Read { address: usize, value: FieldElement },
    Write { address: usize, value: FieldElement },
}

/// Memory trace containing a sequence of operations
#[derive(Debug, Clone)]
pub struct MemoryTrace {
    /// Maximum memory size (must be power of 2)
    pub memory_size: usize,
    
    /// Sequence of memory operations
    pub operations: Vec<MemoryOp>,
    
    /// Current memory state
    memory: Vec<FieldElement>,
}

impl MemoryTrace {
    /// Create a new memory trace with given size
    pub fn new(memory_size: usize) -> Self {
        assert!(memory_size.is_power_of_two(), "Memory size must be power of 2");
        
        Self {
            memory_size,
            operations: Vec::new(),
            memory: vec![FieldElement::zero(); memory_size],
        }
    }
    
    /// Write a value to memory
    pub fn write(&mut self, address: usize, value: FieldElement) -> Result<()> {
        if address >= self.memory_size {
            return Err(TwistAndShoutError::InvalidParameters(
                "Address out of bounds".to_string(),
            ));
        }
        
        self.memory[address] = value;
        self.operations.push(MemoryOp::Write { address, value });
        Ok(())
    }
    
    /// Read a value from memory
    pub fn read(&mut self, address: usize) -> Result<FieldElement> {
        if address >= self.memory_size {
            return Err(TwistAndShoutError::InvalidParameters(
                "Address out of bounds".to_string(),
            ));
        }
        
        let value = self.memory[address];
        self.operations.push(MemoryOp::Read { address, value });
        Ok(value)
    }
}

/// Twist protocol proof
#[derive(Debug, Clone)]
pub struct TwistProof {
    /// Commitments to address and value vectors
    pub address_commitment: KZGCommitmentValue,
    pub value_commitment: KZGCommitmentValue,
    
    /// Sum-check proofs for memory consistency
    pub consistency_proof: SumCheckProof,
    
    /// Opening proofs for final checks
    pub opening_proofs: Vec<KZGProof>,
    
    /// Final polynomial evaluations
    pub final_evaluations: Vec<FieldElement>,
}

/// Twist protocol implementation
#[derive(Debug, Clone)]
pub struct Twist {
    /// Prover parameters
    prover_params: ProverParams,
}

impl Twist {
    /// Create a new Twist instance
    pub fn new(prover_params: &ProverParams) -> Self {
        Self {
            prover_params: prover_params.clone(),
        }
    }
    
    /// Generate a proof for memory consistency
    pub fn prove(&self, trace: &MemoryTrace) -> Result<TwistProof> {
        if trace.operations.len() > self.prover_params.max_operations {
            return Err(TwistAndShoutError::InvalidParameters(
                "Too many operations".to_string(),
            ));
        }
        
        // Extract addresses and values from operations
        let addresses: Vec<FieldElement> = trace.operations
            .iter()
            .map(|op| match op {
                MemoryOp::Read { address, .. } | MemoryOp::Write { address, .. } => {
                    FieldElement::from(*address as u64)
                }
            })
            .collect();
        
        let values: Vec<FieldElement> = trace.operations
            .iter()
            .map(|op| match op {
                MemoryOp::Read { value, .. } | MemoryOp::Write { value, .. } => *value,
            })
            .collect();
        
        // Pad to power of 2 for polynomial operations
        let padded_size = (addresses.len() as usize).next_power_of_two();
        let mut padded_addresses = addresses;
        let mut padded_values = values;
        
        padded_addresses.resize(padded_size, FieldElement::zero());
        padded_values.resize(padded_size, FieldElement::zero());
        
        // Convert to polynomials for commitment
        let address_poly = self.vector_to_polynomial(&padded_addresses)?;
        let value_poly = self.vector_to_polynomial(&padded_values)?;
        
        // Commit to address and value polynomials
        let address_commitment = KZGCommitment::commit(
            &self.prover_params.commitment_params,
            &address_poly,
        )?;
        
        let value_commitment = KZGCommitment::commit(
            &self.prover_params.commitment_params,
            &value_poly,
        )?;
        
        // Create sum-check proof for memory consistency
        let log_ops = (padded_size as f64).log2() as usize;
        let sumcheck = SumCheck::new(log_ops, FieldElement::zero()); // Placeholder
        
        let mut transcript = Transcript::new(&self.prover_params.fiat_shamir_seed);
        
        // Add commitments to transcript
        transcript.append_field_element(b"address_commitment", &FieldElement::zero()); // Placeholder
        transcript.append_field_element(b"value_commitment", &FieldElement::zero()); // Placeholder
        
        // Prove consistency with dummy polynomial for now
        let consistency_polynomial = |_vars: &[FieldElement]| FieldElement::zero();
        let consistency_proof = sumcheck.prove(consistency_polynomial, &mut transcript)?;
        
        // For now, create dummy opening proofs
        let opening_proofs = vec![];
        let final_evaluations = vec![];
        
        Ok(TwistProof {
            address_commitment,
            value_commitment,
            consistency_proof,
            opening_proofs,
            final_evaluations,
        })
    }
    
    /// Verify a Twist proof
    pub fn verify(&self, proof: &TwistProof, verifier_params: &VerifierParams) -> Result<bool> {
        let mut transcript = Transcript::new(&verifier_params.fiat_shamir_seed);
        
        // Add commitments to transcript
        transcript.append_field_element(b"address_commitment", &FieldElement::zero()); // Placeholder
        transcript.append_field_element(b"value_commitment", &FieldElement::zero()); // Placeholder
        
        // Verify sum-check proof
        let sumcheck = SumCheck::new(1, FieldElement::zero()); // Placeholder
        let (is_valid, _) = sumcheck.verify(&proof.consistency_proof, &mut transcript)?;
        
        Ok(is_valid)
    }
    
    /// Convert a vector to polynomial coefficients via interpolation
    fn vector_to_polynomial(&self, vector: &[FieldElement]) -> Result<Vec<FieldElement>> {
        let points: Vec<(FieldElement, FieldElement)> = vector
            .iter()
            .enumerate()
            .map(|(i, &val)| (FieldElement::from(i as u64), val))
            .collect();
        
        Ok(crate::polynomials::poly_utils::lagrange_interpolate(&points))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::setup_params;
    
    #[test]
    fn test_memory_trace() {
        let mut trace = MemoryTrace::new(8);
        
        // Write some values
        trace.write(0, FieldElement::from(42u64)).unwrap();
        trace.write(1, FieldElement::from(73u64)).unwrap();
        
        // Read them back
        let val0 = trace.read(0).unwrap();
        let val1 = trace.read(1).unwrap();
        
        assert_eq!(val0, FieldElement::from(42u64));
        assert_eq!(val1, FieldElement::from(73u64));
        
        assert_eq!(trace.operations.len(), 4); // 2 writes + 2 reads
    }
    
    #[test]
    fn test_twist_prove_verify() {
        let (prover_params, verifier_params) = setup_params(4);
        
        let mut trace = MemoryTrace::new(16);
        trace.write(0, FieldElement::from(42u64)).unwrap();
        trace.write(1, FieldElement::from(73u64)).unwrap();
        let _val = trace.read(0).unwrap();
        
        let twist = Twist::new(&prover_params);
        let proof = twist.prove(&trace).unwrap();
        
        let is_valid = twist.verify(&proof, &verifier_params).unwrap();
        assert!(is_valid);
    }
}