//! Multilinear polynomial representations and operations.
//!
//! This module provides efficient implementations for multilinear extensions (MLEs)
//! of sparse vectors, which are fundamental to the Twist and Shout protocols.

use crate::utils::{FieldElement, field_utils};
use ark_ff::{Field, Zero, One};
use ark_std::collections::BTreeMap;
use itertools::Itertools;
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

/// A multilinear extension of a vector over a finite field.
/// 
/// For a vector v ∈ F^{2^n}, its multilinear extension is the unique multilinear
/// polynomial f: F^n → F such that f(x) = v[x] for all x ∈ {0,1}^n.
#[derive(Debug, Clone)]
pub struct MultilinearExtension {
    /// Number of variables
    pub num_vars: usize,
    
    /// Evaluations at all Boolean points {0,1}^n
    pub evaluations: Vec<FieldElement>,
}

impl MultilinearExtension {
    /// Create a new multilinear extension from evaluations
    pub fn from_evaluations(evaluations: Vec<FieldElement>) -> Self {
        let num_vars = (evaluations.len() as f64).log2() as usize;
        assert_eq!(1 << num_vars, evaluations.len(), 
                  "Evaluation vector length must be a power of 2");
        
        Self {
            num_vars,
            evaluations,
        }
    }
    
    /// Create a multilinear extension from a sparse representation
    /// Only non-zero entries are provided as (index, value) pairs
    pub fn from_sparse(num_vars: usize, sparse_entries: &[(usize, FieldElement)]) -> Self {
        let size = 1 << num_vars;
        let mut evaluations = vec![FieldElement::zero(); size];
        
        for &(index, value) in sparse_entries {
            assert!(index < size, "Index {} out of bounds for size {}", index, size);
            evaluations[index] = value;
        }
        
        Self {
            num_vars,
            evaluations,
        }
    }
    
    /// Create the multilinear extension of a one-hot vector
    /// one_hot(i) has a 1 at position i and 0s elsewhere
    pub fn one_hot(num_vars: usize, index: usize) -> Self {
        let size = 1 << num_vars;
        assert!(index < size, "Index {} out of bounds for size {}", index, size);
        
        let mut evaluations = vec![FieldElement::zero(); size];
        evaluations[index] = FieldElement::one();
        
        Self {
            num_vars,
            evaluations,
        }
    }
    
    /// Evaluate the multilinear extension at a point r ∈ F^n
    pub fn evaluate(&self, point: &[FieldElement]) -> FieldElement {
        assert_eq!(point.len(), self.num_vars, 
                  "Point dimension must match number of variables");
        
        // Use the multilinear evaluation formula:
        // f(r) = Σ_{x ∈ {0,1}^n} f(x) * ∏_{i=1}^n ((1-r_i)(1-x_i) + r_i * x_i)
        self.evaluations
            .par_iter()
            .enumerate()
            .map(|(index, &eval)| {
                if eval.is_zero() {
                    return FieldElement::zero();
                }
                
                let basis_eval = self.evaluate_basis_polynomial(index, point);
                eval * basis_eval
            })
            .sum()
    }
    
    /// Evaluate the basis polynomial at a point
    /// For index i with binary representation (b₁, ..., bₙ):
    /// ψᵢ(r) = ∏_{j=1}^n ((1-rⱼ)(1-bⱼ) + rⱼ * bⱼ)
    fn evaluate_basis_polynomial(&self, index: usize, point: &[FieldElement]) -> FieldElement {
        let mut result = FieldElement::one();
        
        for j in 0..self.num_vars {
            let bit = (index >> j) & 1;
            let contribution = if bit == 0 {
                FieldElement::one() - point[j]
            } else {
                point[j]
            };
            result *= contribution;
        }
        
        result
    }
    
    /// Partial evaluation: fix the first k variables to given values
    /// Returns a new MLE in the remaining (n-k) variables
    pub fn partial_evaluate(&self, fixed_values: &[FieldElement]) -> MultilinearExtension {
        let k = fixed_values.len();
        assert!(k <= self.num_vars, "Cannot fix more variables than available");
        
        if k == 0 {
            return self.clone();
        }
        
        let new_num_vars = self.num_vars - k;
        let new_size = 1 << new_num_vars;
        let mut new_evaluations = vec![FieldElement::zero(); new_size];
        
        // For each point in the new space, evaluate the original polynomial
        // at the extended point (fixed_values || new_point)
        for new_index in 0..new_size {
            let mut full_point = Vec::with_capacity(self.num_vars);
            full_point.extend_from_slice(fixed_values);
            
            // Add binary representation of new_index
            for j in 0..new_num_vars {
                let bit = (new_index >> j) & 1;
                full_point.push(if bit == 0 { 
                    FieldElement::zero() 
                } else { 
                    FieldElement::one() 
                });
            }
            
            new_evaluations[new_index] = self.evaluate(&full_point);
        }
        
        MultilinearExtension {
            num_vars: new_num_vars,
            evaluations: new_evaluations,
        }
    }
    
    /// Add two multilinear extensions
    pub fn add(&self, other: &MultilinearExtension) -> MultilinearExtension {
        assert_eq!(self.num_vars, other.num_vars, "Number of variables must match");
        
        let evaluations = self.evaluations
            .par_iter()
            .zip(other.evaluations.par_iter())
            .map(|(&a, &b)| a + b)
            .collect();
        
        MultilinearExtension {
            num_vars: self.num_vars,
            evaluations,
        }
    }
    
    /// Multiply by a scalar
    pub fn scalar_mul(&self, scalar: FieldElement) -> MultilinearExtension {
        let evaluations = self.evaluations
            .par_iter()
            .map(|&eval| eval * scalar)
            .collect();
        
        MultilinearExtension {
            num_vars: self.num_vars,
            evaluations,
        }
    }
    
    /// Compute the sum of all evaluations
    pub fn sum_evaluations(&self) -> FieldElement {
        self.evaluations.par_iter().sum()
    }
}

/// Represents a less-than indicator polynomial
/// lt(a, b) = 1 if a < b (in lexicographic order), 0 otherwise
#[derive(Debug, Clone)]
pub struct LessThanPolynomial {
    pub num_vars: usize,
}

impl LessThanPolynomial {
    /// Create a new less-than polynomial for n-bit values
    pub fn new(num_vars: usize) -> Self {
        Self { num_vars }
    }
    
    /// Evaluate lt(a, b) where a and b are field elements representing
    /// binary strings via their least significant bits
    pub fn evaluate_at_field_elements(&self, a: FieldElement, b: FieldElement) -> FieldElement {
        // Convert field elements to binary representations
        let a_bits = self.field_to_bits(a);
        let b_bits = self.field_to_bits(b);
        
        self.evaluate_at_bits(&a_bits, &b_bits)
    }
    
    /// Evaluate lt(a, b) where a and b are given as bit vectors
    pub fn evaluate_at_bits(&self, a_bits: &[bool], b_bits: &[bool]) -> FieldElement {
        assert_eq!(a_bits.len(), self.num_vars);
        assert_eq!(b_bits.len(), self.num_vars);
        
        // Lexicographic comparison: a < b iff there exists i such that
        // a[0..i] = b[0..i] and a[i] = 0, b[i] = 1
        for i in 0..self.num_vars {
            if a_bits[i] && !b_bits[i] {
                return FieldElement::zero(); // a > b at position i
            }
            if !a_bits[i] && b_bits[i] {
                return FieldElement::one();  // a < b at position i
            }
            // If a_bits[i] == b_bits[i], continue to next position
        }
        
        FieldElement::zero() // a == b
    }
    
    /// Get the multilinear extension of the less-than function
    /// Returns MLE over 2n variables (n for each input)
    pub fn to_multilinear_extension(&self) -> MultilinearExtension {
        let total_vars = 2 * self.num_vars;
        let size = 1 << total_vars;
        let mut evaluations = vec![FieldElement::zero(); size];
        
        for index in 0..size {
            // Split index into two n-bit values
            let a_index = index & ((1 << self.num_vars) - 1);
            let b_index = index >> self.num_vars;
            
            let a_bits = self.index_to_bits(a_index);
            let b_bits = self.index_to_bits(b_index);
            
            evaluations[index] = self.evaluate_at_bits(&a_bits, &b_bits);
        }
        
        MultilinearExtension {
            num_vars: total_vars,
            evaluations,
        }
    }
    
    /// Convert field element to bit representation (little-endian)
    fn field_to_bits(&self, elem: FieldElement) -> Vec<bool> {
        let mut bits = Vec::with_capacity(self.num_vars);
        use ark_ff::PrimeField;
        let repr = elem.into_bigint();
        
        for i in 0..self.num_vars {
            let limb_index = i / 64;
            let bit_index = i % 64;
            
            if limb_index < repr.0.len() {
                bits.push((repr.0[limb_index] >> bit_index) & 1 == 1);
            } else {
                bits.push(false);
            }
        }
        
        bits
    }
    
    /// Convert index to bit representation
    fn index_to_bits(&self, index: usize) -> Vec<bool> {
        let mut bits = Vec::with_capacity(self.num_vars);
        for i in 0..self.num_vars {
            bits.push((index >> i) & 1 == 1);
        }
        bits
    }
}

/// Utility functions for polynomial operations
pub mod poly_utils {
    use super::*;
    
    /// Interpolate a polynomial from a set of (point, value) pairs
    /// Uses Lagrange interpolation for small sets
    pub fn lagrange_interpolate(points: &[(FieldElement, FieldElement)]) -> Vec<FieldElement> {
        let n = points.len();
        if n == 0 {
            return vec![];
        }
        
        let mut result = vec![FieldElement::zero(); n];
        
        for i in 0..n {
            let (xi, yi) = points[i];
            
            // Compute Lagrange basis polynomial Li(x)
            let mut li_coeffs = vec![FieldElement::one()]; // Start with constant 1
            
            for j in 0..n {
                if i == j {
                    continue;
                }
                
                let (xj, _) = points[j];
                let denominator = xi - xj;
                let denom_inv = denominator.inverse().unwrap();
                
                // Multiply by (x - xj) / (xi - xj)
                let mut new_coeffs = vec![FieldElement::zero(); li_coeffs.len() + 1];
                
                // Multiply by x
                for k in 0..li_coeffs.len() {
                    new_coeffs[k + 1] += li_coeffs[k];
                }
                
                // Subtract xj
                for k in 0..li_coeffs.len() {
                    new_coeffs[k] -= li_coeffs[k] * xj;
                }
                
                // Divide by (xi - xj)
                for k in 0..new_coeffs.len() {
                    new_coeffs[k] *= denom_inv;
                }
                
                li_coeffs = new_coeffs;
            }
            
            // Add yi * Li(x) to result
            for k in 0..li_coeffs.len().min(result.len()) {
                result[k] += yi * li_coeffs[k];
            }
        }
        
        result
    }
    
    /// Evaluate polynomial using Horner's method
    pub fn evaluate_polynomial(coeffs: &[FieldElement], point: FieldElement) -> FieldElement {
        field_utils::horner_eval(coeffs, point)
    }
    
    /// Compute the derivative of a polynomial
    pub fn derivative(coeffs: &[FieldElement]) -> Vec<FieldElement> {
        if coeffs.len() <= 1 {
            return vec![FieldElement::zero()];
        }
        
        coeffs.iter()
            .enumerate()
            .skip(1)
            .map(|(i, &coeff)| coeff * FieldElement::from(i as u64))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_std::test_rng;
    use ark_ff::UniformRand;
    
    #[test]
    fn test_multilinear_extension_evaluation() {
        // Test with simple 2-variable polynomial
        let evaluations = vec![
            FieldElement::from(1u64), // f(0,0) = 1
            FieldElement::from(2u64), // f(1,0) = 2  
            FieldElement::from(3u64), // f(0,1) = 3
            FieldElement::from(4u64), // f(1,1) = 4
        ];
        
        let mle = MultilinearExtension::from_evaluations(evaluations);
        
        // Test evaluation at Boolean points
        assert_eq!(mle.evaluate(&[FieldElement::zero(), FieldElement::zero()]), 
                  FieldElement::from(1u64));
        assert_eq!(mle.evaluate(&[FieldElement::one(), FieldElement::zero()]), 
                  FieldElement::from(2u64));
        assert_eq!(mle.evaluate(&[FieldElement::zero(), FieldElement::one()]), 
                  FieldElement::from(3u64));
        assert_eq!(mle.evaluate(&[FieldElement::one(), FieldElement::one()]), 
                  FieldElement::from(4u64));
        
        // Test evaluation at random point
        let mut rng = test_rng();
        let r1 = FieldElement::rand(&mut rng);
        let r2 = FieldElement::rand(&mut rng);
        
        // Manually compute expected value
        let expected = FieldElement::from(1u64) * (FieldElement::one() - r1) * (FieldElement::one() - r2)
                     + FieldElement::from(2u64) * r1 * (FieldElement::one() - r2)
                     + FieldElement::from(3u64) * (FieldElement::one() - r1) * r2
                     + FieldElement::from(4u64) * r1 * r2;
        
        assert_eq!(mle.evaluate(&[r1, r2]), expected);
    }
    
    #[test]
    fn test_one_hot_polynomial() {
        let mle = MultilinearExtension::one_hot(3, 5); // Index 5 = 101 in binary
        
        // Should be 1 at index 5, 0 elsewhere
        for i in 0..8 {
            let bits = (0..3).map(|j| {
                if (i >> j) & 1 == 1 { FieldElement::one() } else { FieldElement::zero() }
            }).collect::<Vec<_>>();
            
            let expected = if i == 5 { FieldElement::one() } else { FieldElement::zero() };
            assert_eq!(mle.evaluate(&bits), expected);
        }
    }
    
    #[test]
    fn test_less_than_polynomial() {
        let lt_poly = LessThanPolynomial::new(3);
        
        // Test some comparisons
        assert_eq!(lt_poly.evaluate_at_bits(&[false, false, false], &[true, false, false]), 
                  FieldElement::one());  // 0 < 1
        assert_eq!(lt_poly.evaluate_at_bits(&[true, false, false], &[false, false, false]), 
                  FieldElement::zero()); // 1 > 0
        assert_eq!(lt_poly.evaluate_at_bits(&[true, false, false], &[true, false, false]), 
                  FieldElement::zero()); // 1 == 1
        assert_eq!(lt_poly.evaluate_at_bits(&[false, true, false], &[true, false, false]), 
                  FieldElement::one());  // 2 < 1 in little-endian: false
    }
    
    #[test]
    fn test_partial_evaluation() {
        let evaluations = vec![
            FieldElement::from(1u64), FieldElement::from(2u64),
            FieldElement::from(3u64), FieldElement::from(4u64),
        ];
        let mle = MultilinearExtension::from_evaluations(evaluations);
        
        // Fix first variable to 1
        let partial = mle.partial_evaluate(&[FieldElement::one()]);
        
        // Should have evaluations [2, 4] (corresponding to f(1,0) and f(1,1))
        assert_eq!(partial.num_vars, 1);
        assert_eq!(partial.evaluate(&[FieldElement::zero()]), FieldElement::from(2u64));
        assert_eq!(partial.evaluate(&[FieldElement::one()]), FieldElement::from(4u64));
    }
    
    #[test]
    fn test_polynomial_operations() {
        let eval1 = vec![FieldElement::from(1u64), FieldElement::from(2u64)];
        let eval2 = vec![FieldElement::from(3u64), FieldElement::from(4u64)];
        
        let mle1 = MultilinearExtension::from_evaluations(eval1);
        let mle2 = MultilinearExtension::from_evaluations(eval2);
        
        // Test addition
        let sum = mle1.add(&mle2);
        assert_eq!(sum.evaluations, vec![FieldElement::from(4u64), FieldElement::from(6u64)]);
        
        // Test scalar multiplication
        let scaled = mle1.scalar_mul(FieldElement::from(3u64));
        assert_eq!(scaled.evaluations, vec![FieldElement::from(3u64), FieldElement::from(6u64)]);
    }
}