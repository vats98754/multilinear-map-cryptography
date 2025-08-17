//! Sum-check protocol implementation.
//!
//! The sum-check protocol is a fundamental building block for the Twist and Shout protocols.
//! It allows a prover to convince a verifier that the sum of a multivariate polynomial
//! over the Boolean hypercube equals a claimed value.

use crate::utils::{FieldElement, Transcript};
use crate::polynomials::MultilinearExtension;
use crate::{Result, TwistAndShoutError};
use ark_ff::{Field, Zero, One};
use serde::{Deserialize, Serialize};

/// Sum-check protocol instance
#[derive(Debug, Clone)]
pub struct SumCheck {
    /// Number of variables in the polynomial
    pub num_vars: usize,
    
    /// Claimed sum over the Boolean hypercube
    pub claimed_sum: FieldElement,
}

/// Sum-check proof
#[derive(Debug, Clone)]
pub struct SumCheckProof {
    /// Univariate polynomials for each round
    pub round_polynomials: Vec<Vec<FieldElement>>,
    
    /// Final evaluation of the polynomial
    pub final_evaluation: FieldElement,
}

/// Sum-check verifier state
#[derive(Debug, Clone)]
pub struct SumCheckVerifier {
    /// Number of variables
    pub num_vars: usize,
    
    /// Random challenges from the verifier
    pub challenges: Vec<FieldElement>,
    
    /// Expected sum at each round
    pub expected_sum: FieldElement,
}

impl SumCheck {
    /// Create a new sum-check instance
    pub fn new(num_vars: usize, claimed_sum: FieldElement) -> Self {
        Self {
            num_vars,
            claimed_sum,
        }
    }
    
    /// Prove that a polynomial sums to the claimed value over {0,1}^n
    pub fn prove<F>(
        &self,
        polynomial: F,
        transcript: &mut Transcript,
    ) -> Result<SumCheckProof>
    where
        F: Fn(&[FieldElement]) -> FieldElement,
    {
        let mut round_polynomials = Vec::with_capacity(self.num_vars);
        let mut current_sum = self.claimed_sum;
        let mut fixed_variables = Vec::new();
        
        for round in 0..self.num_vars {
            // Compute the univariate polynomial for this round
            let round_poly = self.compute_round_polynomial(
                &polynomial,
                &fixed_variables,
                round,
            )?;
            
            // Check that g(0) + g(1) equals the expected sum
            let g_0 = self.evaluate_round_polynomial(&round_poly, FieldElement::zero());
            let g_1 = self.evaluate_round_polynomial(&round_poly, FieldElement::one());
            
            if g_0 + g_1 != current_sum {
                return Err(TwistAndShoutError::SumCheck(
                    format!("Round {} consistency check failed", round),
                ));
            }
            
            // Add polynomial to proof
            round_polynomials.push(round_poly.clone());
            
            // Get challenge from verifier
            transcript.append_field_elements(
                format!("sumcheck_round_{}", round).as_bytes(),
                &round_poly,
            );
            let challenge = transcript.challenge_field_element(
                format!("sumcheck_challenge_{}", round).as_bytes(),
            );
            
            // Update state for next round
            fixed_variables.push(challenge);
            current_sum = self.evaluate_round_polynomial(&round_poly, challenge);
        }
        
        // Final evaluation
        let final_evaluation = polynomial(&fixed_variables);
        
        Ok(SumCheckProof {
            round_polynomials,
            final_evaluation,
        })
    }
    
    /// Verify a sum-check proof
    pub fn verify(
        &self,
        proof: &SumCheckProof,
        transcript: &mut Transcript,
    ) -> Result<(bool, Vec<FieldElement>)> {
        if proof.round_polynomials.len() != self.num_vars {
            return Err(TwistAndShoutError::SumCheck(
                "Proof has wrong number of rounds".to_string(),
            ));
        }
        
        let mut current_sum = self.claimed_sum;
        let mut challenges = Vec::with_capacity(self.num_vars);
        
        for (round, round_poly) in proof.round_polynomials.iter().enumerate() {
            // Check that g(0) + g(1) equals the expected sum
            let g_0 = self.evaluate_round_polynomial(round_poly, FieldElement::zero());
            let g_1 = self.evaluate_round_polynomial(round_poly, FieldElement::one());
            
            if g_0 + g_1 != current_sum {
                return Ok((false, challenges));
            }
            
            // Generate challenge
            transcript.append_field_elements(
                format!("sumcheck_round_{}", round).as_bytes(),
                round_poly,
            );
            let challenge = transcript.challenge_field_element(
                format!("sumcheck_challenge_{}", round).as_bytes(),
            );
            
            challenges.push(challenge);
            
            // Update expected sum for next round
            current_sum = self.evaluate_round_polynomial(round_poly, challenge);
        }
        
        // The final sum should match the final evaluation
        Ok((current_sum == proof.final_evaluation, challenges))
    }
    
    /// Compute the univariate polynomial for a given round
    fn compute_round_polynomial<F>(
        &self,
        polynomial: &F,
        fixed_variables: &[FieldElement],
        _round: usize,
    ) -> Result<Vec<FieldElement>>
    where
        F: Fn(&[FieldElement]) -> FieldElement,
    {
        // We need to compute g(X) = Σ_{x_{round+1},...,x_n ∈ {0,1}^{n-round-1}} f(fixed_vars, X, x_{round+1}, ..., x_n)
        
        let remaining_vars = self.num_vars - fixed_variables.len() - 1;
        let num_points = 1 << remaining_vars;
        
        // Sample points to determine the degree of the univariate polynomial
        let mut evaluations = Vec::new();
        
        // Evaluate at X = 0, 1, 2, ... to get enough points for interpolation
        // The degree should be at most the degree of the original polynomial in this variable
        for x_val in 0..=3 {  // Assume degree <= 3 for now, can be made adaptive
            let x = FieldElement::from(x_val as u64);
            let mut sum = FieldElement::zero();
            
            for suffix_index in 0..num_points {
                let mut point = Vec::with_capacity(self.num_vars);
                point.extend_from_slice(fixed_variables);
                point.push(x);
                
                // Add the remaining variables from suffix_index
                for bit in 0..remaining_vars {
                    let bit_value = if (suffix_index >> bit) & 1 == 1 {
                        FieldElement::one()
                    } else {
                        FieldElement::zero()
                    };
                    point.push(bit_value);
                }
                
                sum += polynomial(&point);
            }
            
            evaluations.push(sum);
        }
        
        // Interpolate to get polynomial coefficients
        let points: Vec<(FieldElement, FieldElement)> = (0..evaluations.len())
            .map(|i| (FieldElement::from(i as u64), evaluations[i]))
            .collect();
        
        let coeffs = crate::polynomials::poly_utils::lagrange_interpolate(&points);
        Ok(coeffs)
    }
    
    /// Evaluate a univariate polynomial given as coefficients
    fn evaluate_round_polynomial(&self, coeffs: &[FieldElement], point: FieldElement) -> FieldElement {
        crate::utils::field_utils::horner_eval(coeffs, point)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::utils::setup_params;
    
    #[test]
    fn test_sumcheck_simple() {
        let (_, _) = setup_params(2);
        
        // Test with a simple polynomial: f(x1, x2) = x1 * x2
        let polynomial = |vars: &[FieldElement]| -> FieldElement {
            if vars.len() != 2 {
                panic!("Expected 2 variables");
            }
            vars[0] * vars[1]
        };
        
        // Sum over {0,1}^2: f(0,0) + f(0,1) + f(1,0) + f(1,1) = 0 + 0 + 0 + 1 = 1
        let claimed_sum = FieldElement::one();
        
        let sumcheck = SumCheck::new(2, claimed_sum);
        let mut transcript = Transcript::new(&[42u8; 32]);
        
        let proof = sumcheck.prove(polynomial, &mut transcript).unwrap();
        
        // Verify the proof
        let mut verify_transcript = Transcript::new(&[42u8; 32]);
        let (is_valid, _challenges) = sumcheck.verify(&proof, &mut verify_transcript).unwrap();
        
        assert!(is_valid);
    }
}