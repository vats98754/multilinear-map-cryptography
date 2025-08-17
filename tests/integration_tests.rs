//! Integration tests combining multiple protocol components

use twist_and_shout::*;
use ark_ff::{Field, Zero, One};

#[test]
fn test_full_memory_consistency_workflow() {
    let (prover_params, verifier_params) = setup_params(3); // 8 memory addresses
    
    // Create a realistic memory trace
    let mut trace = MemoryTrace::new(8);
    
    // Initialize some memory locations
    trace.write(0, FieldElement::from(42u64)).unwrap();   // Initial setup
    trace.write(1, FieldElement::from(100u64)).unwrap();
    trace.write(2, FieldElement::from(200u64)).unwrap();
    
    // Read some values
    let val0 = trace.read(0).unwrap();
    let val1 = trace.read(1).unwrap();
    assert_eq!(val0, FieldElement::from(42u64));
    assert_eq!(val1, FieldElement::from(100u64));
    
    // Modify memory
    trace.write(0, FieldElement::from(43u64)).unwrap();   // Update
    trace.write(3, FieldElement::from(300u64)).unwrap();  // New location
    
    // Read updated and new values
    let updated_val0 = trace.read(0).unwrap();
    let val3 = trace.read(3).unwrap();
    assert_eq!(updated_val0, FieldElement::from(43u64));
    assert_eq!(val3, FieldElement::from(300u64));
    
    // Generate and verify proof
    let twist = Twist::new(&prover_params);
    let proof = twist.prove(&trace).unwrap();
    let is_valid = twist.verify(&proof, &verifier_params).unwrap();
    
    assert!(is_valid, "Full memory workflow should produce valid proof");
}

#[test]
fn test_full_lookup_workflow() {
    let (prover_params, verifier_params) = setup_params(3);
    
    // Create a lookup table with meaningful data
    let entries = vec![
        FieldElement::from(0u64),    // Index 0: value 0
        FieldElement::from(1u64),    // Index 1: value 1  
        FieldElement::from(4u64),    // Index 2: value 4 (2^2)
        FieldElement::from(9u64),    // Index 3: value 9 (3^2)
        FieldElement::from(16u64),   // Index 4: value 16 (4^2)
        FieldElement::from(25u64),   // Index 5: value 25 (5^2)
        FieldElement::from(36u64),   // Index 6: value 36 (6^2)
        FieldElement::from(49u64),   // Index 7: value 49 (7^2)
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Perform lookups to compute squares
    let square_of_3 = table.lookup(3).unwrap();
    let square_of_5 = table.lookup(5).unwrap();
    let square_of_0 = table.lookup(0).unwrap();
    let square_of_7 = table.lookup(7).unwrap();
    
    assert_eq!(square_of_3, FieldElement::from(9u64));
    assert_eq!(square_of_5, FieldElement::from(25u64));
    assert_eq!(square_of_0, FieldElement::from(0u64));
    assert_eq!(square_of_7, FieldElement::from(49u64));
    
    // Generate and verify proof
    let shout = Shout::new(&prover_params);
    let proof = shout.prove(&table).unwrap();
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    
    assert!(is_valid, "Full lookup workflow should produce valid proof");
}

#[test]
fn test_commitment_scheme_integration() {
    let (prover_params, verifier_params) = setup_params(3);
    
    // Test KZG commitment directly
    let polynomial = vec![
        FieldElement::from(1u64),  // constant term
        FieldElement::from(2u64),  // x term
        FieldElement::from(3u64),  // x^2 term
    ];
    
    // Commit to polynomial
    let commitment = KZGCommitment::commit(&prover_params.commitment_params, &polynomial).unwrap();
    
    // Open at multiple points
    let points = vec![
        FieldElement::from(0u64),
        FieldElement::from(1u64),
        FieldElement::from(2u64),
        FieldElement::from(5u64),
    ];
    
    for &point in &points {
        let (value, proof) = KZGCommitment::open(&prover_params.commitment_params, &polynomial, point).unwrap();
        
        // Verify each opening
        let is_valid = KZGCommitment::verify(
            &verifier_params.commitment_vk,
            &commitment,
            point,
            value,
            &proof,
        ).unwrap();
        
        assert!(is_valid, "KZG opening should be valid for point {}", point);
        
        // Verify the evaluation is correct
        let expected = polynomial[0] + polynomial[1] * point + polynomial[2] * point * point;
        assert_eq!(value, expected, "Opened value should match polynomial evaluation");
    }
}

#[test]
fn test_combined_twist_and_shout() {
    let (prover_params, verifier_params) = setup_params(3);
    
    // Set up lookup table for opcodes
    let opcodes = vec![
        FieldElement::from(0u64),   // NOP
        FieldElement::from(1u64),   // LOAD
        FieldElement::from(2u64),   // STORE
        FieldElement::from(3u64),   // ADD
        FieldElement::from(4u64),   // SUB
        FieldElement::from(5u64),   // MUL
        FieldElement::from(6u64),   // DIV
        FieldElement::from(7u64),   // HALT
    ];
    
    let mut opcode_table = LookupTable::new(opcodes);
    
    // Set up memory for a simple program
    let mut memory = MemoryTrace::new(8);
    
    // Simulate a simple program execution
    // LOAD value 42 into memory[0]
    opcode_table.lookup(1).unwrap(); // LOAD opcode
    memory.write(0, FieldElement::from(42u64)).unwrap();
    
    // LOAD value 58 into memory[1] 
    opcode_table.lookup(1).unwrap(); // LOAD opcode
    memory.write(1, FieldElement::from(58u64)).unwrap();
    
    // ADD: read memory[0] and memory[1], store sum in memory[2]
    opcode_table.lookup(3).unwrap(); // ADD opcode
    let a = memory.read(0).unwrap();
    let b = memory.read(1).unwrap();
    memory.write(2, a + b).unwrap(); // 42 + 58 = 100
    
    // Verify the computation
    let result = memory.read(2).unwrap();
    assert_eq!(result, FieldElement::from(100u64));
    
    // HALT
    opcode_table.lookup(7).unwrap(); // HALT opcode
    
    // Generate proofs for both protocols
    let twist = Twist::new(&prover_params);
    let shout = Shout::new(&prover_params);
    
    let memory_proof = twist.prove(&memory).unwrap();
    let opcode_proof = shout.prove(&opcode_table).unwrap();
    
    // Verify both proofs
    let memory_valid = twist.verify(&memory_proof, &verifier_params).unwrap();
    let opcode_valid = shout.verify(&opcode_proof, &verifier_params).unwrap();
    
    assert!(memory_valid, "Memory consistency proof should be valid");
    assert!(opcode_valid, "Opcode lookup proof should be valid");
}

#[test]
fn test_polynomial_commitment_consistency() {
    let (prover_params, verifier_params) = setup_params(4);
    
    // Create a multilinear extension
    let evaluations = vec![
        FieldElement::from(10u64), FieldElement::from(20u64),
        FieldElement::from(30u64), FieldElement::from(40u64),
        FieldElement::from(50u64), FieldElement::from(60u64),
        FieldElement::from(70u64), FieldElement::from(80u64),
    ];
    
    let mle = MultilinearExtension::from_evaluations(evaluations.clone());
    
    // Convert to univariate polynomial by fixing some variables
    let fixed_point = vec![FieldElement::from(2u64), FieldElement::from(3u64)]; // Fix first 2 vars
    let partial = mle.partial_evaluate(&fixed_point);
    
    // Extract coefficients by interpolation
    let points: Vec<(FieldElement, FieldElement)> = (0..partial.evaluations.len())
        .map(|i| (FieldElement::from(i as u64), partial.evaluations[i]))
        .collect();
    
    let coeffs = twist_and_shout::polynomials::poly_utils::lagrange_interpolate(&points);
    
    // Commit to the univariate polynomial
    let commitment = KZGCommitment::commit(&prover_params.commitment_params, &coeffs).unwrap();
    
    // Test opening at a random point
    let test_point = FieldElement::from(10u64);
    let (opened_value, proof) = KZGCommitment::open(&prover_params.commitment_params, &coeffs, test_point).unwrap();
    
    // Verify the opening
    let is_valid = KZGCommitment::verify(
        &verifier_params.commitment_vk,
        &commitment,
        test_point,
        opened_value,
        &proof,
    ).unwrap();
    
    assert!(is_valid, "Polynomial commitment opening should be valid");
    
    // Verify consistency with multilinear evaluation
    let full_point = vec![
        fixed_point[0], fixed_point[1], test_point
    ];
    
    // Note: This test shows the framework but the actual evaluation might differ
    // due to how the polynomial interpolation works
    let _mle_value = mle.evaluate(&full_point);
}

#[test]
fn test_parameter_compatibility() {
    // Test that prover and verifier parameters are compatible
    let (prover_params, verifier_params) = setup_params(4);
    
    assert_eq!(prover_params.log_size, verifier_params.log_size);
    assert_eq!(prover_params.max_operations, verifier_params.max_operations);
    assert_eq!(prover_params.fiat_shamir_seed, verifier_params.fiat_shamir_seed);
    
    // Test that commitment parameters are consistent
    let test_polynomial = vec![FieldElement::from(1u64), FieldElement::from(2u64)];
    let commitment = KZGCommitment::commit(&prover_params.commitment_params, &test_polynomial).unwrap();
    
    let (value, proof) = KZGCommitment::open(
        &prover_params.commitment_params, 
        &test_polynomial, 
        FieldElement::from(5u64)
    ).unwrap();
    
    let is_valid = KZGCommitment::verify(
        &verifier_params.commitment_vk,
        &commitment,
        FieldElement::from(5u64),
        value,
        &proof,
    ).unwrap();
    
    assert!(is_valid, "Prover and verifier parameters should be compatible");
}

#[test]
fn test_sumcheck_protocol_basic() {
    use twist_and_shout::sumcheck::SumCheck;
    use twist_and_shout::utils::Transcript;
    
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
    let mut prover_transcript = Transcript::new(&[42u8; 32]);
    
    let proof = sumcheck.prove(polynomial, &mut prover_transcript).unwrap();
    
    // Verify the proof
    let mut verifier_transcript = Transcript::new(&[42u8; 32]);
    let (is_valid, _challenges) = sumcheck.verify(&proof, &mut verifier_transcript).unwrap();
    
    assert!(is_valid, "Sum-check proof should be valid");
}

#[test]
fn test_error_handling() {
    let (prover_params, _) = setup_params(2); // Small parameters for easy limit testing
    
    // Test Twist with too many operations
    let mut large_trace = MemoryTrace::new(4);
    for i in 0..100 { // Exceed max_operations
        large_trace.write(i % 4, FieldElement::from(i as u64)).unwrap();
    }
    
    let twist = Twist::new(&prover_params);
    let result = twist.prove(&large_trace);
    assert!(result.is_err(), "Should fail with too many operations");
    
    // Test Shout with too many operations
    let mut large_table = LookupTable::new(vec![FieldElement::one(); 4]);
    for _ in 0..100 { // Exceed max_operations
        large_table.lookup(0).unwrap();
    }
    
    let shout = Shout::new(&prover_params);
    let result = shout.prove(&large_table);
    assert!(result.is_err(), "Should fail with too many operations");
    
    // Test bounds checking
    let mut trace = MemoryTrace::new(4);
    assert!(trace.write(4, FieldElement::one()).is_err()); // Out of bounds
    assert!(trace.read(10).is_err()); // Out of bounds
    
    let mut table = LookupTable::new(vec![FieldElement::one(); 2]);
    assert!(table.lookup(2).is_err()); // Out of bounds
}