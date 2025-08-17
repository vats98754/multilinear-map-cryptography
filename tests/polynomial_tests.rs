//! Tests for polynomial operations and multilinear extensions

use twist_and_shout::*;
use ark_ff::{Field, Zero, One, UniformRand};
use ark_std::test_rng;

#[test]
fn test_multilinear_extension_creation() {
    // Test creating from evaluations
    let evaluations = vec![
        FieldElement::from(1u64),
        FieldElement::from(2u64),
        FieldElement::from(3u64),
        FieldElement::from(4u64),
    ];
    
    let mle = MultilinearExtension::from_evaluations(evaluations.clone());
    assert_eq!(mle.num_vars, 2);
    assert_eq!(mle.evaluations, evaluations);
}

#[test]
fn test_multilinear_extension_power_of_two_requirement() {
    // Should work with power of 2
    let evaluations = vec![FieldElement::one(); 8]; // 2^3
    let mle = MultilinearExtension::from_evaluations(evaluations);
    assert_eq!(mle.num_vars, 3);
    
    // Should panic with non-power of 2
    let result = std::panic::catch_unwind(|| {
        let evaluations = vec![FieldElement::one(); 7]; // Not power of 2
        MultilinearExtension::from_evaluations(evaluations)
    });
    assert!(result.is_err());
}

#[test]
fn test_multilinear_extension_from_sparse() {
    let sparse_entries = vec![
        (0, FieldElement::from(10u64)),
        (2, FieldElement::from(30u64)),
        (5, FieldElement::from(60u64)),
    ];
    
    let mle = MultilinearExtension::from_sparse(3, &sparse_entries); // 2^3 = 8 elements
    
    assert_eq!(mle.num_vars, 3);
    assert_eq!(mle.evaluations[0], FieldElement::from(10u64));
    assert_eq!(mle.evaluations[1], FieldElement::zero());
    assert_eq!(mle.evaluations[2], FieldElement::from(30u64));
    assert_eq!(mle.evaluations[3], FieldElement::zero());
    assert_eq!(mle.evaluations[4], FieldElement::zero());
    assert_eq!(mle.evaluations[5], FieldElement::from(60u64));
    assert_eq!(mle.evaluations[6], FieldElement::zero());
    assert_eq!(mle.evaluations[7], FieldElement::zero());
}

#[test]
fn test_one_hot_polynomial() {
    let mle = MultilinearExtension::one_hot(3, 5); // Set bit at position 5 (101 in binary)
    
    assert_eq!(mle.num_vars, 3);
    
    // Should be 1 at position 5, 0 elsewhere
    for i in 0..8 {
        if i == 5 {
            assert_eq!(mle.evaluations[i], FieldElement::one());
        } else {
            assert_eq!(mle.evaluations[i], FieldElement::zero());
        }
    }
}

#[test]
fn test_multilinear_extension_evaluation_at_boolean_points() {
    let evaluations = vec![
        FieldElement::from(1u64), // f(0,0) = 1
        FieldElement::from(2u64), // f(1,0) = 2
        FieldElement::from(3u64), // f(0,1) = 3
        FieldElement::from(4u64), // f(1,1) = 4
    ];
    
    let mle = MultilinearExtension::from_evaluations(evaluations);
    
    // Test evaluation at Boolean points
    assert_eq!(mle.evaluate(&[FieldElement::zero(), FieldElement::zero()]), FieldElement::from(1u64));
    assert_eq!(mle.evaluate(&[FieldElement::one(), FieldElement::zero()]), FieldElement::from(2u64));
    assert_eq!(mle.evaluate(&[FieldElement::zero(), FieldElement::one()]), FieldElement::from(3u64));
    assert_eq!(mle.evaluate(&[FieldElement::one(), FieldElement::one()]), FieldElement::from(4u64));
}

#[test]
fn test_multilinear_extension_evaluation_at_random_points() {
    let evaluations = vec![
        FieldElement::from(1u64),
        FieldElement::from(2u64),
        FieldElement::from(3u64),
        FieldElement::from(4u64),
    ];
    
    let mle = MultilinearExtension::from_evaluations(evaluations);
    
    // Test at point (1/2, 1/2)
    let half = FieldElement::from(2u64).inverse().unwrap();
    let result = mle.evaluate(&[half, half]);
    
    // Manual calculation: (1+2+3+4)/4 = 2.5
    let expected = (FieldElement::from(1u64) + FieldElement::from(2u64) + 
                   FieldElement::from(3u64) + FieldElement::from(4u64)) * 
                   FieldElement::from(4u64).inverse().unwrap();
    assert_eq!(result, expected);
}

#[test]
fn test_partial_evaluation() {
    let evaluations = vec![
        FieldElement::from(1u64), // f(0,0) = 1
        FieldElement::from(2u64), // f(1,0) = 2
        FieldElement::from(3u64), // f(0,1) = 3
        FieldElement::from(4u64), // f(1,1) = 4
    ];
    
    let mle = MultilinearExtension::from_evaluations(evaluations);
    
    // Fix first variable to 1, should get g(y) = f(1,y) = 2*(1-y) + 4*y = 2 + 2*y
    let partial = mle.partial_evaluate(&[FieldElement::one()]);
    
    assert_eq!(partial.num_vars, 1);
    assert_eq!(partial.evaluate(&[FieldElement::zero()]), FieldElement::from(2u64)); // g(0) = 2
    assert_eq!(partial.evaluate(&[FieldElement::one()]), FieldElement::from(4u64));  // g(1) = 4
}

#[test]
fn test_polynomial_arithmetic() {
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
    
    // Test sum of evaluations
    let total = mle1.sum_evaluations();
    assert_eq!(total, FieldElement::from(3u64)); // 1 + 2 = 3
}

#[test]
fn test_less_than_polynomial() {
    use twist_and_shout::polynomials::LessThanPolynomial;
    
    let lt = LessThanPolynomial::new(3); // 3-bit comparisons
    
    // Test basic comparisons
    assert_eq!(lt.evaluate_at_bits(&[false, false, false], &[true, false, false]), FieldElement::one());  // 0 < 1
    assert_eq!(lt.evaluate_at_bits(&[true, false, false], &[false, false, false]), FieldElement::zero()); // 1 > 0
    assert_eq!(lt.evaluate_at_bits(&[true, false, false], &[true, false, false]), FieldElement::zero());  // 1 == 1
    
    // Test with larger numbers (little-endian)
    assert_eq!(lt.evaluate_at_bits(&[false, true, false], &[true, true, false]), FieldElement::one());   // 2 < 3
    assert_eq!(lt.evaluate_at_bits(&[true, true, false], &[false, true, false]), FieldElement::zero());  // 3 > 2
}

#[test]
fn test_less_than_polynomial_multilinear_extension() {
    use twist_and_shout::polynomials::LessThanPolynomial;
    
    let lt = LessThanPolynomial::new(2); // 2-bit comparisons
    let mle = lt.to_multilinear_extension();
    
    // Should have 4 variables (2 for each input)
    assert_eq!(mle.num_vars, 4);
    
    // Test some evaluations
    // Point (0,0,0,1) corresponds to a=00, b=01, so a < b should be true
    let point1 = vec![FieldElement::zero(), FieldElement::zero(), FieldElement::zero(), FieldElement::one()];
    assert_eq!(mle.evaluate(&point1), FieldElement::one());
    
    // Point (0,1,0,0) corresponds to a=01, b=00, so a > b should be false
    let point2 = vec![FieldElement::zero(), FieldElement::one(), FieldElement::zero(), FieldElement::zero()];
    assert_eq!(mle.evaluate(&point2), FieldElement::zero());
}

#[test]
fn test_lagrange_interpolation() {
    use twist_and_shout::polynomials::poly_utils;
    
    // Interpolate the polynomial f(x) = x^2 from points (0,0), (1,1), (2,4)
    let points = vec![
        (FieldElement::zero(), FieldElement::zero()),
        (FieldElement::one(), FieldElement::one()),
        (FieldElement::from(2u64), FieldElement::from(4u64)),
    ];
    
    let coeffs = poly_utils::lagrange_interpolate(&points);
    
    // Should give coefficients [0, 0, 1] for f(x) = x^2
    assert_eq!(coeffs.len(), 3);
    assert_eq!(coeffs[0], FieldElement::zero());  // constant term
    assert_eq!(coeffs[1], FieldElement::zero());  // x term
    assert_eq!(coeffs[2], FieldElement::one());   // x^2 term
}

#[test]
fn test_polynomial_evaluation() {
    use twist_and_shout::polynomials::poly_utils;
    
    // Evaluate f(x) = 3x^2 + 2x + 1 at x = 5
    let coeffs = vec![
        FieldElement::one(),              // constant: 1
        FieldElement::from(2u64),         // x: 2
        FieldElement::from(3u64),         // x^2: 3
    ];
    
    let result = poly_utils::evaluate_polynomial(&coeffs, FieldElement::from(5u64));
    
    // Expected: 3*25 + 2*5 + 1 = 75 + 10 + 1 = 86
    assert_eq!(result, FieldElement::from(86u64));
}

#[test]
fn test_polynomial_derivative() {
    use twist_and_shout::polynomials::poly_utils;
    
    // Derivative of f(x) = 3x^3 + 2x^2 + x + 5 should be f'(x) = 9x^2 + 4x + 1
    let coeffs = vec![
        FieldElement::from(5u64),  // constant: 5
        FieldElement::one(),       // x: 1
        FieldElement::from(2u64),  // x^2: 2
        FieldElement::from(3u64),  // x^3: 3
    ];
    
    let derivative = poly_utils::derivative(&coeffs);
    
    // Expected: [1, 4, 9] for f'(x) = 1 + 4x + 9x^2
    assert_eq!(derivative.len(), 3);
    assert_eq!(derivative[0], FieldElement::one());       // constant: 1
    assert_eq!(derivative[1], FieldElement::from(4u64));  // x: 4
    assert_eq!(derivative[2], FieldElement::from(9u64));  // x^2: 9
}

#[test]
fn test_sparse_multilinear_extension() {
    // Test with a very sparse polynomial
    let sparse_entries = vec![
        (0, FieldElement::from(100u64)),
        (7, FieldElement::from(700u64)),
    ];
    
    let mle = MultilinearExtension::from_sparse(3, &sparse_entries);
    
    // Evaluate at points where it should be non-zero
    let point_0 = vec![FieldElement::zero(), FieldElement::zero(), FieldElement::zero()]; // Index 0
    let point_7 = vec![FieldElement::one(), FieldElement::one(), FieldElement::one()];   // Index 7
    
    assert_eq!(mle.evaluate(&point_0), FieldElement::from(100u64));
    assert_eq!(mle.evaluate(&point_7), FieldElement::from(700u64));
    
    // Evaluate at a point where it should be zero
    let point_3 = vec![FieldElement::one(), FieldElement::one(), FieldElement::zero()];  // Index 3
    assert_eq!(mle.evaluate(&point_3), FieldElement::zero());
}

#[test]
fn test_multilinear_extension_random_evaluation() {
    let mut rng = test_rng();
    
    // Create random evaluations
    let evaluations: Vec<FieldElement> = (0..16)
        .map(|_| FieldElement::rand(&mut rng))
        .collect();
    
    let mle = MultilinearExtension::from_evaluations(evaluations.clone());
    
    // Test that evaluation at Boolean points matches the evaluations
    for i in 0..16 {
        let mut point = Vec::new();
        for j in 0..4 {
            let bit = (i >> j) & 1;
            point.push(if bit == 1 { FieldElement::one() } else { FieldElement::zero() });
        }
        
        assert_eq!(mle.evaluate(&point), evaluations[i]);
    }
}

#[test]
fn test_multilinear_extension_properties() {
    let eval1 = vec![
        FieldElement::from(1u64), FieldElement::from(2u64),
        FieldElement::from(3u64), FieldElement::from(4u64),
    ];
    let eval2 = vec![
        FieldElement::from(5u64), FieldElement::from(6u64),
        FieldElement::from(7u64), FieldElement::from(8u64),
    ];
    
    let mle1 = MultilinearExtension::from_evaluations(eval1);
    let mle2 = MultilinearExtension::from_evaluations(eval2);
    
    // Test linearity: evaluation of sum = sum of evaluations
    let sum_mle = mle1.add(&mle2);
    let test_point = vec![FieldElement::from(3u64), FieldElement::from(7u64)];
    
    let sum_eval = sum_mle.evaluate(&test_point);
    let individual_sum = mle1.evaluate(&test_point) + mle2.evaluate(&test_point);
    
    assert_eq!(sum_eval, individual_sum);
    
    // Test scalar multiplication
    let scalar = FieldElement::from(5u64);
    let scaled_mle = mle1.scalar_mul(scalar);
    let scaled_eval = scaled_mle.evaluate(&test_point);
    let expected_scaled = mle1.evaluate(&test_point) * scalar;
    
    assert_eq!(scaled_eval, expected_scaled);
}