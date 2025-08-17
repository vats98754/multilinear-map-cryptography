//! Comprehensive tests for the Shout protocol

use twist_and_shout::*;
use ark_ff::{Field, Zero, One};

#[test]
fn test_lookup_table_basic_operations() {
    let entries = vec![
        FieldElement::from(10u64),
        FieldElement::from(20u64),
        FieldElement::from(30u64),
        FieldElement::from(40u64),
        FieldElement::from(50u64),
    ];
    
    let mut table = LookupTable::new(entries.clone());
    
    // Test lookups
    assert_eq!(table.lookup(0).unwrap(), FieldElement::from(10u64));
    assert_eq!(table.lookup(2).unwrap(), FieldElement::from(30u64));
    assert_eq!(table.lookup(4).unwrap(), FieldElement::from(50u64));
    
    // Test that lookups are recorded
    assert_eq!(table.lookups.len(), 3);
    
    // Test size
    assert_eq!(table.size(), 5);
}

#[test]
fn test_lookup_table_bounds_checking() {
    let entries = vec![
        FieldElement::from(100u64),
        FieldElement::from(200u64),
        FieldElement::from(300u64),
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Valid lookups
    assert!(table.lookup(0).is_ok());
    assert!(table.lookup(1).is_ok());
    assert!(table.lookup(2).is_ok());
    
    // Out of bounds lookups should fail
    assert!(table.lookup(3).is_err());
    assert!(table.lookup(100).is_err());
}

#[test]
fn test_lookup_table_empty() {
    let mut table = LookupTable::new(vec![]);
    
    // Should be empty
    assert_eq!(table.size(), 0);
    
    // Any lookup should fail
    assert!(table.lookup(0).is_err());
}

#[test]
fn test_lookup_table_single_entry() {
    let mut table = LookupTable::new(vec![FieldElement::from(42u64)]);
    
    assert_eq!(table.size(), 1);
    assert_eq!(table.lookup(0).unwrap(), FieldElement::from(42u64));
    assert!(table.lookup(1).is_err());
}

#[test]
fn test_shout_protocol_basic_lookup() {
    let (prover_params, verifier_params) = setup_params(3); // Support larger tables
    
    let entries = vec![
        FieldElement::from(100u64),
        FieldElement::from(200u64),
        FieldElement::from(300u64),
        FieldElement::from(400u64),
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Perform some lookups
    table.lookup(0).unwrap();
    table.lookup(2).unwrap();
    table.lookup(3).unwrap();
    table.lookup(1).unwrap();
    
    let shout = Shout::new(&prover_params);
    
    // Generate proof
    let proof = shout.prove(&table).unwrap();
    
    // Verify proof
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Shout proof should be valid for correct lookups");
}

#[test]
fn test_shout_protocol_no_lookups() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let entries = vec![
        FieldElement::from(10u64),
        FieldElement::from(20u64),
        FieldElement::from(30u64),
        FieldElement::from(40u64),
    ];
    
    let table = LookupTable::new(entries); // No lookups performed
    
    let shout = Shout::new(&prover_params);
    
    // Should be able to prove table with no lookups
    let proof = shout.prove(&table).unwrap();
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Table with no lookups should have valid proof");
}

#[test]
fn test_shout_protocol_single_lookup() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let entries = vec![
        FieldElement::from(1000u64),
        FieldElement::from(2000u64),
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Single lookup
    table.lookup(1).unwrap();
    
    let shout = Shout::new(&prover_params);
    
    let proof = shout.prove(&table).unwrap();
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Single lookup should have valid proof");
}

#[test]
fn test_shout_protocol_repeated_lookups() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let entries = vec![
        FieldElement::from(111u64),
        FieldElement::from(222u64),
        FieldElement::from(333u64),
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Repeated lookups to same indices
    table.lookup(0).unwrap();
    table.lookup(0).unwrap();
    table.lookup(1).unwrap();
    table.lookup(0).unwrap();
    table.lookup(2).unwrap();
    table.lookup(1).unwrap();
    
    let shout = Shout::new(&prover_params);
    
    let proof = shout.prove(&table).unwrap();
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Repeated lookups should have valid proof");
}

#[test]
fn test_shout_protocol_all_indices() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let entries = vec![
        FieldElement::from(10u64),
        FieldElement::from(20u64),
        FieldElement::from(30u64),
        FieldElement::from(40u64),
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Look up all indices in order
    for i in 0..4 {
        table.lookup(i).unwrap();
    }
    
    let shout = Shout::new(&prover_params);
    
    let proof = shout.prove(&table).unwrap();
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Lookup of all indices should have valid proof");
}

#[test]
fn test_shout_protocol_reverse_order() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let entries = vec![
        FieldElement::from(100u64),
        FieldElement::from(200u64),
        FieldElement::from(300u64),
        FieldElement::from(400u64),
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Look up indices in reverse order
    for i in (0..4).rev() {
        table.lookup(i).unwrap();
    }
    
    let shout = Shout::new(&prover_params);
    
    let proof = shout.prove(&table).unwrap();
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Reverse order lookups should have valid proof");
}

#[test]
fn test_shout_protocol_large_table() {
    let (prover_params, verifier_params) = setup_params(4); // Support up to 16 entries
    
    // Create larger table
    let entries: Vec<FieldElement> = (0..16)
        .map(|i| FieldElement::from((i * 10) as u64))
        .collect();
    
    let mut table = LookupTable::new(entries);
    
    // Perform various lookups
    let lookup_indices = vec![0, 5, 10, 15, 2, 8, 1, 14];
    for &index in &lookup_indices {
        table.lookup(index).unwrap();
    }
    
    let shout = Shout::new(&prover_params);
    
    let proof = shout.prove(&table).unwrap();
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Large table lookups should have valid proof");
}

#[test]
fn test_shout_protocol_exceeds_operations_limit() {
    let (prover_params, _) = setup_params(1); // Small limit for testing
    
    let entries = vec![
        FieldElement::from(1u64),
        FieldElement::from(2u64),
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Exceed the operations limit with many lookups
    for _ in 0..20 {
        table.lookup(0).unwrap();
    }
    
    let shout = Shout::new(&prover_params);
    
    // Should fail to generate proof due to too many operations
    let result = shout.prove(&table);
    assert!(result.is_err(), "Should fail when exceeding operation limit");
}

#[test]
fn test_lookup_op_structure() {
    use twist_and_shout::LookupOp;
    
    let op = LookupOp {
        index: 5,
        value: FieldElement::from(42u64),
    };
    
    assert_eq!(op.index, 5);
    assert_eq!(op.value, FieldElement::from(42u64));
    
    // Test copy semantics
    let op2 = op;
    assert_eq!(op.index, op2.index);
    assert_eq!(op.value, op2.value);
}

#[test]
fn test_shout_protocol_zero_values() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let entries = vec![
        FieldElement::zero(),
        FieldElement::from(100u64),
        FieldElement::zero(),
        FieldElement::from(200u64),
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Look up zero values and non-zero values
    table.lookup(0).unwrap(); // zero
    table.lookup(1).unwrap(); // non-zero
    table.lookup(2).unwrap(); // zero
    table.lookup(3).unwrap(); // non-zero
    
    let shout = Shout::new(&prover_params);
    
    let proof = shout.prove(&table).unwrap();
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Lookups with zero values should have valid proof");
}

#[test]
fn test_shout_protocol_duplicate_values() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let entries = vec![
        FieldElement::from(100u64),
        FieldElement::from(200u64),
        FieldElement::from(100u64), // Duplicate of entry 0
        FieldElement::from(300u64),
    ];
    
    let mut table = LookupTable::new(entries);
    
    // Look up duplicate values
    table.lookup(0).unwrap(); // 100
    table.lookup(2).unwrap(); // 100 (duplicate)
    table.lookup(1).unwrap(); // 200
    
    let shout = Shout::new(&prover_params);
    
    let proof = shout.prove(&table).unwrap();
    let is_valid = shout.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Lookups with duplicate values should have valid proof");
}