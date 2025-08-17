//! Example usage of the Twist and Shout protocols

use twist_and_shout::*;
use ark_ff::{Field, Zero, One};

fn main() {
    println!("🚀 Twist and Shout: zk-SNARK Memory Checking Demo");
    println!("==================================================");
    
    // Set up parameters for small examples
    let (prover_params, verifier_params) = setup_params(3); // 8 memory cells
    
    // Example 1: Memory Consistency with Twist Protocol
    println!("\n📝 Example 1: Memory Consistency (Twist Protocol)");
    demo_memory_consistency(&prover_params, &verifier_params);
    
    // Example 2: Lookup Operations with Shout Protocol  
    println!("\n🔍 Example 2: Lookup Table (Shout Protocol)");
    demo_lookup_table(&prover_params, &verifier_params);
    
    // Example 3: Polynomial Commitments
    println!("\n🔒 Example 3: Polynomial Commitments (KZG)");
    demo_polynomial_commitments(&prover_params, &verifier_params);
    
    // Example 4: Multilinear Extensions
    println!("\n🧮 Example 4: Multilinear Extensions");
    demo_multilinear_extensions();
    
    println!("\n✅ All examples completed successfully!");
}

fn demo_memory_consistency(prover_params: &ProverParams, verifier_params: &VerifierParams) {
    let mut trace = MemoryTrace::new(8);
    
    println!("   Initializing memory...");
    trace.write(0, FieldElement::from(42u64)).unwrap();
    trace.write(1, FieldElement::from(100u64)).unwrap();
    println!("   Wrote: memory[0] = 42, memory[1] = 100");
    
    let val0 = trace.read(0).unwrap();
    let val1 = trace.read(1).unwrap();
    println!("   Read: memory[0] = {}, memory[1] = {}", 
             field_to_u64(val0), field_to_u64(val1));
    
    trace.write(0, FieldElement::from(43u64)).unwrap(); // Update
    let updated_val = trace.read(0).unwrap();
    println!("   Updated: memory[0] = {}", field_to_u64(updated_val));
    
    println!("   Total operations: {}", trace.operations.len());
    
    // Generate proof (would work with full implementation)
    let twist = Twist::new(prover_params);
    match twist.prove(&trace) {
        Ok(proof) => {
            match twist.verify(&proof, verifier_params) {
                Ok(valid) => println!("   ✅ Proof generated and verified: {}", valid),
                Err(e) => println!("   ⚠️  Verification failed: {}", e),
            }
        }
        Err(e) => println!("   ⚠️  Proof generation failed (expected with stub): {}", e),
    }
}

fn demo_lookup_table(prover_params: &ProverParams, verifier_params: &VerifierParams) {
    // Create a lookup table for square numbers
    let squares: Vec<FieldElement> = (0..8)
        .map(|i| FieldElement::from((i * i) as u64))
        .collect();
    
    let mut table = LookupTable::new(squares);
    
    println!("   Lookup table contains squares: [0, 1, 4, 9, 16, 25, 36, 49]");
    
    // Perform some lookups
    let lookup_indices = vec![3, 5, 0, 7];
    for &index in &lookup_indices {
        let value = table.lookup(index).unwrap();
        println!("   Lookup: square of {} = {}", index, field_to_u64(value));
    }
    
    println!("   Total lookups: {}", table.lookups.len());
    
    // Generate proof (would work with full implementation)
    let shout = Shout::new(prover_params);
    match shout.prove(&table) {
        Ok(proof) => {
            match shout.verify(&proof, verifier_params) {
                Ok(valid) => println!("   ✅ Proof generated and verified: {}", valid),
                Err(e) => println!("   ⚠️  Verification failed: {}", e),
            }
        }
        Err(e) => println!("   ⚠️  Proof generation failed (expected with stub): {}", e),
    }
}

fn demo_polynomial_commitments(prover_params: &ProverParams, verifier_params: &VerifierParams) {
    // Commit to polynomial f(x) = 3x^2 + 2x + 1
    let polynomial = vec![
        FieldElement::from(1u64),  // constant term
        FieldElement::from(2u64),  // x term  
        FieldElement::from(3u64),  // x^2 term
    ];
    
    println!("   Polynomial: f(x) = 3x² + 2x + 1");
    
    // Commit to the polynomial
    let commitment = KZGCommitment::commit(&prover_params.commitment_params, &polynomial)
        .expect("Commitment should succeed");
    
    println!("   ✅ Polynomial committed successfully");
    
    // Open at point x = 5
    let point = FieldElement::from(5u64);
    let (value, proof) = KZGCommitment::open(&prover_params.commitment_params, &polynomial, point)
        .expect("Opening should succeed");
    
    println!("   Opened at x = 5, value = {}", field_to_u64(value));
    
    // Verify the opening
    let is_valid = KZGCommitment::verify(
        &verifier_params.commitment_vk,
        &commitment,
        point,
        value,
        &proof,
    ).expect("Verification should succeed");
    
    println!("   ✅ Opening verified: {}", is_valid);
    
    // Check the math: f(5) = 3*25 + 2*5 + 1 = 86
    let expected = FieldElement::from(86u64);
    assert_eq!(value, expected);
    println!("   ✅ Value matches expected: 3×25 + 2×5 + 1 = 86");
}

fn demo_multilinear_extensions() {
    // Create a multilinear extension from a simple truth table
    let evaluations = vec![
        FieldElement::from(0u64),  // f(0,0) = 0
        FieldElement::from(1u64),  // f(1,0) = 1  
        FieldElement::from(1u64),  // f(0,1) = 1
        FieldElement::from(0u64),  // f(1,1) = 0 (XOR function)
    ];
    
    let mle = MultilinearExtension::from_evaluations(evaluations);
    
    println!("   Created MLE for XOR function: f(x,y) = x ⊕ y");
    
    // Evaluate at Boolean points
    let test_points = vec![
        (vec![FieldElement::zero(), FieldElement::zero()], 0u64),
        (vec![FieldElement::one(), FieldElement::zero()], 1u64),
        (vec![FieldElement::zero(), FieldElement::one()], 1u64),
        (vec![FieldElement::one(), FieldElement::one()], 0u64),
    ];
    
    for (point, expected) in test_points {
        let result = mle.evaluate(&point);
        let point_str = format!("({},{})", 
                               field_to_u64(point[0]), 
                               field_to_u64(point[1]));
        println!("   f{} = {} (expected {})", 
                point_str, field_to_u64(result), expected);
        assert_eq!(result, FieldElement::from(expected));
    }
    
    // Evaluate at a random point
    let random_point = vec![
        FieldElement::from(3u64),
        FieldElement::from(7u64),
    ];
    let random_result = mle.evaluate(&random_point);
    println!("   f(3,7) = {} (interpolated)", field_to_u64(random_result));
    
    // Test one-hot polynomial
    let one_hot = MultilinearExtension::one_hot(3, 5); // Position 5 in 3-bit space
    println!("   One-hot polynomial: 1 at position 5, 0 elsewhere");
    
    let pos5_point = vec![
        FieldElement::one(),   // bit 0
        FieldElement::zero(),  // bit 1  
        FieldElement::one(),   // bit 2 (5 = 101 in binary)
    ];
    let result = one_hot.evaluate(&pos5_point);
    println!("   Position 5 (101): {}", field_to_u64(result));
    assert_eq!(result, FieldElement::one());
    
    let pos3_point = vec![
        FieldElement::one(),   // bit 0
        FieldElement::one(),   // bit 1
        FieldElement::zero(),  // bit 2 (3 = 011 in binary)
    ];
    let result = one_hot.evaluate(&pos3_point);
    println!("   Position 3 (011): {}", field_to_u64(result));
    assert_eq!(result, FieldElement::zero());
}

// Helper function to convert field element to u64 for display
fn field_to_u64(element: FieldElement) -> u64 {
    use ark_ff::PrimeField;
    let repr = element.into_bigint();
    if repr.0.is_empty() {
        0
    } else {
        repr.0[0]
    }
}