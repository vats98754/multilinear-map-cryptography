//! Polynomial and vector commitment schemes.
//!
//! This module provides commitment schemes used in the Twist and Shout protocols,
//! with KZG commitments as the default implementation.

use crate::utils::{FieldElement, G1Element, G2Element, CommitmentParams, CommitmentVerificationKey};
use crate::{Result, TwistAndShoutError};
use ark_ec::{CurveGroup, Group, pairing::Pairing};
use ark_bn254::{Bn254, G1Affine, G2Affine};
use ark_ff::{Field, Zero, One, PrimeField, BigInteger};
use ark_serialize::{CanonicalSerialize, CanonicalDeserialize};
use serde::{Deserialize, Serialize};

/// Trait defining a polynomial commitment scheme
pub trait CommitmentScheme {
    type Commitment: Clone + PartialEq;
    type Proof: Clone;
    type Params: Clone;
    type VerifyKey: Clone;
    
    /// Commit to a polynomial represented by its coefficients
    fn commit(
        params: &Self::Params,
        polynomial: &[FieldElement],
    ) -> Result<Self::Commitment>;
    
    /// Open the commitment at a given point
    fn open(
        params: &Self::Params,
        polynomial: &[FieldElement],
        point: FieldElement,
    ) -> Result<(FieldElement, Self::Proof)>;
    
    /// Verify an opening proof
    fn verify(
        vk: &Self::VerifyKey,
        commitment: &Self::Commitment,
        point: FieldElement,
        value: FieldElement,
        proof: &Self::Proof,
    ) -> Result<bool>;
    
    /// Batch verify multiple opening proofs (optional optimization)
    fn batch_verify(
        vk: &Self::VerifyKey,
        commitments: &[Self::Commitment],
        points: &[FieldElement],
        values: &[FieldElement],
        proofs: &[Self::Proof],
    ) -> Result<bool> {
        // Default implementation: verify each proof individually
        for i in 0..commitments.len() {
            if !Self::verify(vk, &commitments[i], points[i], values[i], &proofs[i])? {
                return Ok(false);
            }
        }
        Ok(true)
    }
}

/// KZG polynomial commitment scheme using BN254 curve
#[derive(Debug, Clone)]
pub struct KZGCommitment;

/// KZG commitment (a point in G1)
#[derive(Debug, Clone, PartialEq)]
pub struct KZGCommitmentValue {
    pub commitment: G1Element,
}

impl KZGCommitmentValue {
    /// Get a field element hash of the commitment for transcripts
    pub fn hash(&self) -> FieldElement {
        // Convert the x-coordinate to a scalar field element via modular reduction
        let x_coord = self.commitment.into_affine().x;
        let x_bytes = x_coord.into_bigint().to_bytes_le();
        
        // Create a field element from the first 32 bytes
        let mut bytes = [0u8; 32];
        let copy_len = std::cmp::min(x_bytes.len(), 32);
        bytes[..copy_len].copy_from_slice(&x_bytes[..copy_len]);
        
        FieldElement::from_le_bytes_mod_order(&bytes)
    }
}

/// KZG opening proof (a point in G1)
#[derive(Debug, Clone)]
pub struct KZGProof {
    pub proof: G1Element,
}

// Manual implementations for arkworks compatibility
impl ark_serialize::Valid for KZGCommitmentValue {
    fn check(&self) -> std::result::Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl ark_serialize::Valid for KZGProof {
    fn check(&self) -> std::result::Result<(), ark_serialize::SerializationError> {
        Ok(())
    }
}

impl ark_serialize::CanonicalSerialize for KZGCommitmentValue {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> std::result::Result<(), ark_serialize::SerializationError> {
        self.commitment.serialize_with_mode(writer, compress)
    }
    
    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.commitment.serialized_size(compress)
    }
}

impl ark_serialize::CanonicalDeserialize for KZGCommitmentValue {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> std::result::Result<Self, ark_serialize::SerializationError> {
        let commitment = G1Element::deserialize_with_mode(reader, compress, validate)?;
        Ok(Self { commitment })
    }
}

impl ark_serialize::CanonicalSerialize for KZGProof {
    fn serialize_with_mode<W: ark_serialize::Write>(
        &self,
        writer: W,
        compress: ark_serialize::Compress,
    ) -> std::result::Result<(), ark_serialize::SerializationError> {
        self.proof.serialize_with_mode(writer, compress)
    }
    
    fn serialized_size(&self, compress: ark_serialize::Compress) -> usize {
        self.proof.serialized_size(compress)
    }
}

impl ark_serialize::CanonicalDeserialize for KZGProof {
    fn deserialize_with_mode<R: ark_serialize::Read>(
        reader: R,
        compress: ark_serialize::Compress,
        validate: ark_serialize::Validate,
    ) -> std::result::Result<Self, ark_serialize::SerializationError> {
        let proof = G1Element::deserialize_with_mode(reader, compress, validate)?;
        Ok(Self { proof })
    }
}

impl CommitmentScheme for KZGCommitment {
    type Commitment = KZGCommitmentValue;
    type Proof = KZGProof;
    type Params = CommitmentParams;
    type VerifyKey = CommitmentVerificationKey;
    
    fn commit(
        params: &Self::Params,
        polynomial: &[FieldElement],
    ) -> Result<Self::Commitment> {
        if polynomial.len() > params.g1_powers.len() {
            return Err(TwistAndShoutError::Commitment(
                "Polynomial degree exceeds setup size".to_string(),
            ));
        }
        
        // Compute commitment: C = Σᵢ cᵢ * [τⁱ]₁ where cᵢ are coefficients
        let commitment = polynomial
            .iter()
            .zip(params.g1_powers.iter())
            .map(|(&coeff, &generator)| generator * coeff)
            .sum::<G1Element>();
        
        Ok(KZGCommitmentValue { commitment })
    }
    
    fn open(
        params: &Self::Params,
        polynomial: &[FieldElement],
        point: FieldElement,
    ) -> Result<(FieldElement, Self::Proof)> {
        // Evaluate polynomial at the point
        let value = evaluate_polynomial(polynomial, point);
        
        // Compute quotient polynomial Q(x) = (P(x) - P(z)) / (x - z)
        let quotient = compute_quotient_polynomial(polynomial, point, value)?;
        
        // Commit to quotient polynomial
        let proof_commitment = Self::commit(params, &quotient)?;
        
        Ok((value, KZGProof {
            proof: proof_commitment.commitment,
        }))
    }
    
    fn verify(
        vk: &Self::VerifyKey,
        commitment: &Self::Commitment,
        point: FieldElement,
        value: FieldElement,
        proof: &Self::Proof,
    ) -> Result<bool> {
        // Verify the pairing equation:
        // e(C - [value]₁, [1]₂) = e(π, [τ]₂ - [point]₂)
        
        let value_in_g1 = vk.g1_generator * value;
        let left_g1 = commitment.commitment - value_in_g1;
        
        let point_in_g2 = vk.g2_generator * point;
        let right_g2 = vk.g2_tau - point_in_g2;
        
        // Convert to affine for pairing
        let left_g1_affine = left_g1.into_affine();
        let g2_gen_affine = vk.g2_generator.into_affine();
        let proof_affine = proof.proof.into_affine();
        let right_g2_affine = right_g2.into_affine();
        
        // Check pairing equation: e(left_g1, g2_gen) = e(proof, right_g2)
        let left_pairing = Bn254::pairing(left_g1_affine, g2_gen_affine);
        let right_pairing = Bn254::pairing(proof_affine, right_g2_affine);
        
        Ok(left_pairing == right_pairing)
    }
    
    fn batch_verify(
        vk: &Self::VerifyKey,
        commitments: &[Self::Commitment],
        points: &[FieldElement],
        values: &[FieldElement],
        proofs: &[Self::Proof],
    ) -> Result<bool> {
        if commitments.len() != points.len() 
            || points.len() != values.len() 
            || values.len() != proofs.len() {
            return Err(TwistAndShoutError::Commitment(
                "Batch verify input lengths must match".to_string(),
            ));
        }
        
        if commitments.is_empty() {
            return Ok(true);
        }
        
        // Use random linear combination for batch verification
        use ark_std::rand::SeedableRng;
        let mut rng = rand_chacha::ChaCha20Rng::from_seed([42u8; 32]);
        use ark_ff::UniformRand;
        let challenges: Vec<FieldElement> = (0..commitments.len())
            .map(|_| FieldElement::rand(&mut rng))
            .collect();
        
        // Compute batched commitment: Σᵢ γᵢ * Cᵢ
        let batched_commitment = commitments
            .iter()
            .zip(challenges.iter())
            .map(|(c, &gamma)| c.commitment * gamma)
            .sum::<G1Element>();
        
        // Compute batched value: Σᵢ γᵢ * vᵢ
        let batched_value = values
            .iter()
            .zip(challenges.iter())
            .map(|(&v, &gamma)| v * gamma)
            .sum::<FieldElement>();
        
        // Compute batched proof: Σᵢ γᵢ * πᵢ
        let batched_proof = proofs
            .iter()
            .zip(challenges.iter())
            .map(|(p, &gamma)| p.proof * gamma)
            .sum::<G1Element>();
        
        // We need to verify: e(batched_commitment - [batched_value]₁, [1]₂) = 
        //                   e(batched_proof, Σᵢ γᵢ * ([τ]₂ - [zᵢ]₂))
        
        let value_in_g1 = vk.g1_generator * batched_value;
        let left_g1 = batched_commitment - value_in_g1;
        
        // Compute batched G2 element: Σᵢ γᵢ * ([τ]₂ - [zᵢ]₂)
        let batched_g2 = points
            .iter()
            .zip(challenges.iter())
            .map(|(&point, &gamma)| (vk.g2_tau - vk.g2_generator * point) * gamma)
            .sum::<G2Element>();
        
        // Check pairing equation
        let left_g1_affine = left_g1.into_affine();
        let g2_gen_affine = vk.g2_generator.into_affine();
        let batched_proof_affine = batched_proof.into_affine();
        let batched_g2_affine = batched_g2.into_affine();
        
        let left_pairing = Bn254::pairing(left_g1_affine, g2_gen_affine);
        let right_pairing = Bn254::pairing(batched_proof_affine, batched_g2_affine);
        
        Ok(left_pairing == right_pairing)
    }
}

/// Evaluate a polynomial at a given point using Horner's method
fn evaluate_polynomial(coeffs: &[FieldElement], point: FieldElement) -> FieldElement {
    if coeffs.is_empty() {
        return FieldElement::zero();
    }
    
    coeffs.iter().rev().fold(FieldElement::zero(), |acc, &coeff| {
        acc * point + coeff
    })
}

/// Compute the quotient polynomial Q(x) = (P(x) - v) / (x - z)
/// where P(z) = v
fn compute_quotient_polynomial(
    poly: &[FieldElement], 
    point: FieldElement, 
    value: FieldElement
) -> Result<Vec<FieldElement>> {
    if poly.is_empty() {
        return Ok(vec![]);
    }
    
    // Create P(x) - v by subtracting v from the constant term
    let mut shifted_poly = poly.to_vec();
    shifted_poly[0] -= value;
    
    // Compute (P(x) - v) / (x - z) using polynomial long division
    let quotient = polynomial_division(&shifted_poly, &[-point, FieldElement::one()])?;
    
    Ok(quotient)
}

/// Divide polynomial p(x) by q(x), returning the quotient
/// Assumes q(x) divides p(x) exactly
fn polynomial_division(dividend: &[FieldElement], divisor: &[FieldElement]) -> Result<Vec<FieldElement>> {
    if divisor.is_empty() || divisor.iter().all(|&x| x.is_zero()) {
        return Err(TwistAndShoutError::Polynomial("Cannot divide by zero polynomial".to_string()));
    }
    
    let mut remainder = dividend.to_vec();
    let divisor_degree = divisor.len() - 1;
    
    // Find the leading coefficient of divisor
    let leading_coeff = divisor[divisor_degree];
    if leading_coeff.is_zero() {
        return Err(TwistAndShoutError::Polynomial("Divisor must have non-zero leading coefficient".to_string()));
    }
    let leading_coeff_inv = leading_coeff.inverse().unwrap();
    
    if remainder.len() < divisor.len() {
        return Ok(vec![]); // Quotient is zero
    }
    
    let quotient_degree = remainder.len() - divisor.len();
    let mut quotient = vec![FieldElement::zero(); quotient_degree + 1];
    
    for i in (0..=quotient_degree).rev() {
        if remainder.len() > i + divisor_degree {
            let coeff = remainder[i + divisor_degree] * leading_coeff_inv;
            quotient[i] = coeff;
            
            // Subtract coeff * divisor * x^i from remainder
            for j in 0..divisor.len() {
                if i + j < remainder.len() {
                    remainder[i + j] -= coeff * divisor[j];
                }
            }
        }
    }
    
    Ok(quotient)
}

/// Vector commitment scheme trait
pub trait VectorCommitmentScheme {
    type Commitment: Clone + PartialEq;
    type Proof: Clone;
    type Params: Clone;
    type VerifyKey: Clone;
    
    /// Commit to a vector
    fn commit(
        params: &Self::Params,
        vector: &[FieldElement],
    ) -> Result<Self::Commitment>;
    
    /// Open the commitment at a given index
    fn open(
        params: &Self::Params,
        vector: &[FieldElement],
        index: usize,
    ) -> Result<(FieldElement, Self::Proof)>;
    
    /// Verify an opening proof
    fn verify(
        vk: &Self::VerifyKey,
        commitment: &Self::Commitment,
        index: usize,
        value: FieldElement,
        proof: &Self::Proof,
    ) -> Result<bool>;
}

/// Vector commitment using KZG over the interpolation of the vector
pub struct KZGVectorCommitment;

impl VectorCommitmentScheme for KZGVectorCommitment {
    type Commitment = KZGCommitmentValue;
    type Proof = KZGProof;
    type Params = CommitmentParams;
    type VerifyKey = CommitmentVerificationKey;
    
    fn commit(
        params: &Self::Params,
        vector: &[FieldElement],
    ) -> Result<Self::Commitment> {
        // Interpolate the vector as a polynomial over domain {0, 1, 2, ..., n-1}
        let domain: Vec<FieldElement> = (0..vector.len())
            .map(|i| FieldElement::from(i as u64))
            .collect();
        
        let points: Vec<(FieldElement, FieldElement)> = domain
            .into_iter()
            .zip(vector.iter().cloned())
            .collect();
        
        let poly = crate::polynomials::poly_utils::lagrange_interpolate(&points);
        
        KZGCommitment::commit(params, &poly)
    }
    
    fn open(
        params: &Self::Params,
        vector: &[FieldElement],
        index: usize,
    ) -> Result<(FieldElement, Self::Proof)> {
        if index >= vector.len() {
            return Err(TwistAndShoutError::Commitment(
                "Index out of bounds".to_string(),
            ));
        }
        
        let value = vector[index];
        let point = FieldElement::from(index as u64);
        
        // Interpolate the vector as a polynomial
        let domain: Vec<FieldElement> = (0..vector.len())
            .map(|i| FieldElement::from(i as u64))
            .collect();
        
        let points: Vec<(FieldElement, FieldElement)> = domain
            .into_iter()
            .zip(vector.iter().cloned())
            .collect();
        
        let poly = crate::polynomials::poly_utils::lagrange_interpolate(&points);
        
        let (opened_value, proof) = KZGCommitment::open(params, &poly, point)?;
        
        // Sanity check
        if opened_value != value {
            return Err(TwistAndShoutError::Commitment(
                "Opened value does not match vector entry".to_string(),
            ));
        }
        
        Ok((value, proof))
    }
    
    fn verify(
        vk: &Self::VerifyKey,
        commitment: &Self::Commitment,
        index: usize,
        value: FieldElement,
        proof: &Self::Proof,
    ) -> Result<bool> {
        let point = FieldElement::from(index as u64);
        KZGCommitment::verify(vk, commitment, point, value, proof)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::setup_params;
    
    #[test]
    fn test_kzg_commitment() {
        let (prover_params, verifier_params) = setup_params(4);
        
        // Test polynomial: 3x^2 + 2x + 1
        let poly = vec![
            FieldElement::from(1u64),
            FieldElement::from(2u64),
            FieldElement::from(3u64),
        ];
        
        // Commit to polynomial
        let commitment = KZGCommitment::commit(&prover_params.commitment_params, &poly).unwrap();
        
        // Open at point z = 5
        let point = FieldElement::from(5u64);
        let (value, proof) = KZGCommitment::open(&prover_params.commitment_params, &poly, point).unwrap();
        
        // Expected value: 3*25 + 2*5 + 1 = 86
        assert_eq!(value, FieldElement::from(86u64));
        
        // Verify opening
        let is_valid = KZGCommitment::verify(
            &verifier_params.commitment_vk,
            &commitment,
            point,
            value,
            &proof,
        ).unwrap();
        
        assert!(is_valid);
        
        // Test with wrong value
        let wrong_value = FieldElement::from(87u64);
        let is_invalid = KZGCommitment::verify(
            &verifier_params.commitment_vk,
            &commitment,
            point,
            wrong_value,
            &proof,
        ).unwrap();
        
        assert!(!is_invalid);
    }
    
    #[test]
    fn test_kzg_vector_commitment() {
        let (prover_params, verifier_params) = setup_params(4);
        
        let vector = vec![
            FieldElement::from(10u64),
            FieldElement::from(20u64),
            FieldElement::from(30u64),
            FieldElement::from(40u64),
        ];
        
        // Commit to vector
        let commitment = KZGVectorCommitment::commit(&prover_params.commitment_params, &vector).unwrap();
        
        // Open at index 2
        let index = 2;
        let (value, proof) = KZGVectorCommitment::open(&prover_params.commitment_params, &vector, index).unwrap();
        
        assert_eq!(value, FieldElement::from(30u64));
        
        // Verify opening
        let is_valid = KZGVectorCommitment::verify(
            &verifier_params.commitment_vk,
            &commitment,
            index,
            value,
            &proof,
        ).unwrap();
        
        assert!(is_valid);
    }
    
    #[test]
    fn test_polynomial_division() {
        // Test dividing x^2 - 1 by x - 1, should get x + 1
        let dividend = vec![
            -FieldElement::one(),  // constant term: -1
            FieldElement::zero(),  // x term: 0
            FieldElement::one(),   // x^2 term: 1
        ];
        let divisor = vec![
            -FieldElement::one(),  // constant term: -1 (for x - 1)
            FieldElement::one(),   // x term: 1
        ];
        
        let quotient = polynomial_division(&dividend, &divisor).unwrap();
        
        // Expected: x + 1
        assert_eq!(quotient, vec![
            FieldElement::one(),   // constant term: 1
            FieldElement::one(),   // x term: 1
        ]);
    }
}