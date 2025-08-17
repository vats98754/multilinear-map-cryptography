//! Utility functions, field operations, and parameter setup.
//!
//! This module provides foundational utilities for the Twist and Shout protocols,
//! including field arithmetic, random number generation, and parameter setup.

use ark_ff::{Field, PrimeField, Zero, One};
use ark_bn254::{Fr as Bn254Fr, G1Projective, G2Projective};
use ark_ec::{CurveGroup, Group};
use ark_std::{rand::RngCore, UniformRand, rand::SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde::{Deserialize, Serialize};

/// The field element type used throughout the library
pub type FieldElement = Bn254Fr;

/// Group element for commitments
pub type G1Element = G1Projective;
pub type G2Element = G2Projective;

/// Parameters for the prover
#[derive(Debug, Clone)]
pub struct ProverParams {
    /// Log of memory size (i.e., memory has 2^log_size elements)
    pub log_size: usize,
    
    /// Maximum number of memory operations
    pub max_operations: usize,
    
    /// Setup parameters for commitments
    pub commitment_params: CommitmentParams,
    
    /// Random oracle parameters
    pub fiat_shamir_seed: [u8; 32],
}

/// Parameters for the verifier
#[derive(Debug, Clone)]
pub struct VerifierParams {
    /// Log of memory size
    pub log_size: usize,
    
    /// Maximum number of memory operations
    pub max_operations: usize,
    
    /// Verification parameters for commitments
    pub commitment_vk: CommitmentVerificationKey,
    
    /// Random oracle parameters
    pub fiat_shamir_seed: [u8; 32],
}

/// Commitment scheme parameters
#[derive(Debug, Clone)]
pub struct CommitmentParams {
    /// Generator points for KZG commitments
    pub g1_powers: Vec<G1Element>,
    
    /// G2 generator
    pub g2_generator: G2Element,
    
    /// Trusted setup tau (kept for transparency, not used in production)
    pub tau: Option<FieldElement>,
}

/// Commitment verification key
#[derive(Debug, Clone)]
pub struct CommitmentVerificationKey {
    /// G1 generator
    pub g1_generator: G1Element,
    
    /// G2 generator  
    pub g2_generator: G2Element,
    
    /// G2 element [tau]_2 for pairing checks
    pub g2_tau: G2Element,
}

/// Setup parameters for a given memory size
pub fn setup_params(log_size: usize) -> (ProverParams, VerifierParams) {
    let max_operations = 1 << (log_size + 2); // Allow 4x memory size operations
    let mut rng = ChaCha20Rng::from_seed([42u8; 32]);
    
    // Generate trusted setup for KZG commitments
    let tau = FieldElement::rand(&mut rng);
    let g1_gen = G1Element::generator();
    let g2_gen = G2Element::generator();
    
    // Generate powers of tau in G1: [1, tau, tau^2, ..., tau^max_degree]
    let max_degree = (max_operations as usize).next_power_of_two();
    let mut g1_powers = Vec::with_capacity(max_degree + 1);
    let mut current_tau_power = FieldElement::one();
    
    for _ in 0..=max_degree {
        g1_powers.push(g1_gen * current_tau_power);
        current_tau_power *= tau;
    }
    
    let g2_tau = g2_gen * tau;
    
    // Generate Fiat-Shamir seed
    let mut seed = [0u8; 32];
    rng.fill_bytes(&mut seed);
    
    let commitment_params = CommitmentParams {
        g1_powers,
        g2_generator: g2_gen,
        tau: Some(tau), // Only for testing, remove in production
    };
    
    let commitment_vk = CommitmentVerificationKey {
        g1_generator: g1_gen,
        g2_generator: g2_gen,
        g2_tau,
    };
    
    let prover_params = ProverParams {
        log_size,
        max_operations,
        commitment_params,
        fiat_shamir_seed: seed,
    };
    
    let verifier_params = VerifierParams {
        log_size,
        max_operations,
        commitment_vk,
        fiat_shamir_seed: seed,
    };
    
    (prover_params, verifier_params)
}

/// Fiat-Shamir transcript for non-interactive proofs
pub struct Transcript {
    rng: ChaCha20Rng,
    state: Vec<u8>,
}

impl Transcript {
    /// Create a new transcript with the given seed
    pub fn new(seed: &[u8; 32]) -> Self {
        use ark_std::rand::SeedableRng;
        Self {
            rng: ChaCha20Rng::from_seed(*seed),
            state: Vec::new(),
        }
    }
    
    /// Append a field element to the transcript
    pub fn append_field_element(&mut self, label: &[u8], element: &FieldElement) {
        self.state.extend_from_slice(label);
        
        // Serialize field element
        let mut bytes = Vec::new();
        ark_serialize::CanonicalSerialize::serialize_compressed(element, &mut bytes)
            .expect("Field element serialization should not fail");
        self.state.extend_from_slice(&bytes);
    }
    
    /// Append multiple field elements to the transcript
    pub fn append_field_elements(&mut self, label: &[u8], elements: &[FieldElement]) {
        self.state.extend_from_slice(label);
        for element in elements {
            let mut bytes = Vec::new();
            ark_serialize::CanonicalSerialize::serialize_compressed(element, &mut bytes)
                .expect("Field element serialization should not fail");
            self.state.extend_from_slice(&bytes);
        }
    }
    
    /// Challenge a random field element from the transcript
    pub fn challenge_field_element(&mut self, label: &[u8]) -> FieldElement {
        self.state.extend_from_slice(label);
        
        // Update RNG state with current transcript
        use ark_std::rand::SeedableRng;
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        
        let mut hasher = DefaultHasher::new();
        self.state.hash(&mut hasher);
        let hash = hasher.finish();
        
        let seed = hash.to_le_bytes();
        let mut extended_seed = [0u8; 32];
        for i in 0..4 {
            extended_seed[i * 8..(i + 1) * 8].copy_from_slice(&seed);
        }
        
        self.rng = ChaCha20Rng::from_seed(extended_seed);
        FieldElement::rand(&mut self.rng)
    }
    
    /// Challenge multiple random field elements
    pub fn challenge_field_elements(&mut self, label: &[u8], count: usize) -> Vec<FieldElement> {
        let mut challenges = Vec::with_capacity(count);
        for i in 0..count {
            let indexed_label = format!("{}_{}", 
                std::str::from_utf8(label).unwrap_or("challenge"), i);
            challenges.push(self.challenge_field_element(indexed_label.as_bytes()));
        }
        challenges
    }
}

/// Utility functions for field arithmetic
pub mod field_utils {
    use super::*;
    
    /// Compute the inner product of two field element vectors
    pub fn inner_product(a: &[FieldElement], b: &[FieldElement]) -> FieldElement {
        assert_eq!(a.len(), b.len(), "Vector lengths must match");
        a.iter().zip(b.iter()).map(|(x, y)| *x * y).sum()
    }
    
    /// Evaluate a polynomial at a given point using Horner's method
    pub fn horner_eval(coeffs: &[FieldElement], point: FieldElement) -> FieldElement {
        coeffs.iter().rev().fold(FieldElement::zero(), |acc, &coeff| {
            acc * point + coeff
        })
    }
    
    /// Compute powers of a field element: [1, x, x^2, ..., x^(n-1)]
    pub fn powers(x: FieldElement, n: usize) -> Vec<FieldElement> {
        let mut powers = Vec::with_capacity(n);
        let mut current = FieldElement::one();
        
        for _ in 0..n {
            powers.push(current);
            current *= x;
        }
        
        powers
    }
    
    /// Compute the vanishing polynomial of a set at a given point
    /// Z_S(x) = ∏_{s ∈ S} (x - s)
    pub fn vanishing_poly_eval(set: &[FieldElement], point: FieldElement) -> FieldElement {
        set.iter().map(|&s| point - s).product()
    }
    
    /// Batch inverse using Montgomery's trick
    pub fn batch_inverse(elements: &[FieldElement]) -> Vec<FieldElement> {
        if elements.is_empty() {
            return Vec::new();
        }
        
        let mut acc = Vec::with_capacity(elements.len());
        acc.push(elements[0]);
        
        // Forward pass: compute prefix products
        for i in 1..elements.len() {
            acc.push(acc[i - 1] * elements[i]);
        }
        
        // Inverse of final product
        let mut inv = acc[elements.len() - 1].inverse().unwrap();
        
        // Backward pass: compute inverses
        let mut result = vec![FieldElement::zero(); elements.len()];
        for i in (1..elements.len()).rev() {
            result[i] = inv * acc[i - 1];
            inv *= elements[i];
        }
        result[0] = inv;
        
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    
    #[test]
    fn test_setup_params() {
        let (prover_params, verifier_params) = setup_params(4);
        
        assert_eq!(prover_params.log_size, 4);
        assert_eq!(verifier_params.log_size, 4);
        assert_eq!(prover_params.max_operations, 64); // 2^(4+2)
        assert!(!prover_params.commitment_params.g1_powers.is_empty());
    }
    
    #[test]
    fn test_transcript() {
        let seed = [42u8; 32];
        let mut transcript = Transcript::new(&seed);
        
        let elem = FieldElement::from(123u64);
        transcript.append_field_element(b"test", &elem);
        
        let challenge = transcript.challenge_field_element(b"challenge");
        assert_ne!(challenge, FieldElement::zero());
    }
    
    #[test]
    fn test_field_utils() {
        let mut rng = test_rng();
        
        // Test inner product
        let a = vec![FieldElement::from(1u64), FieldElement::from(2u64)];
        let b = vec![FieldElement::from(3u64), FieldElement::from(4u64)];
        let result = field_utils::inner_product(&a, &b);
        assert_eq!(result, FieldElement::from(11u64)); // 1*3 + 2*4 = 11
        
        // Test powers
        let x = FieldElement::from(2u64);
        let powers = field_utils::powers(x, 4);
        assert_eq!(powers, vec![
            FieldElement::from(1u64),
            FieldElement::from(2u64),
            FieldElement::from(4u64),
            FieldElement::from(8u64),
        ]);
        
        // Test batch inverse
        let elements = vec![
            FieldElement::from(2u64),
            FieldElement::from(3u64),
            FieldElement::from(5u64),
        ];
        let inverses = field_utils::batch_inverse(&elements);
        
        for (elem, inv) in elements.iter().zip(inverses.iter()) {
            assert_eq!(*elem * inv, FieldElement::one());
        }
    }
}