//! Comprehensive tests for the Twist protocol

use twist_and_shout::*;
use ark_ff::{Field, Zero, One};

#[test]
fn test_memory_trace_basic_operations() {
    let mut trace = MemoryTrace::new(16);
    
    // Test writing to different addresses
    assert!(trace.write(0, FieldElement::from(42u64)).is_ok());
    assert!(trace.write(5, FieldElement::from(100u64)).is_ok());
    assert!(trace.write(15, FieldElement::from(255u64)).is_ok());
    
    // Test reading back the values
    assert_eq!(trace.read(0).unwrap(), FieldElement::from(42u64));
    assert_eq!(trace.read(5).unwrap(), FieldElement::from(100u64));
    assert_eq!(trace.read(15).unwrap(), FieldElement::from(255u64));
    
    // Test reading unwritten address (should be zero)
    assert_eq!(trace.read(10).unwrap(), FieldElement::zero());
    
    // Test that operations are recorded
    assert_eq!(trace.operations.len(), 7); // 3 writes + 4 reads
}

#[test]
fn test_memory_trace_write_then_read() {
    let mut trace = MemoryTrace::new(8);
    
    // Write to an address
    trace.write(3, FieldElement::from(123u64)).unwrap();
    
    // Read should return the written value
    let read_value = trace.read(3).unwrap();
    assert_eq!(read_value, FieldElement::from(123u64));
    
    // Overwrite the same address
    trace.write(3, FieldElement::from(456u64)).unwrap();
    
    // Read should return the new value
    let new_read_value = trace.read(3).unwrap();
    assert_eq!(new_read_value, FieldElement::from(456u64));
}

#[test]
fn test_memory_trace_bounds_checking() {
    let mut trace = MemoryTrace::new(4);
    
    // Valid operations
    assert!(trace.write(0, FieldElement::from(1u64)).is_ok());
    assert!(trace.write(3, FieldElement::from(2u64)).is_ok());
    assert!(trace.read(0).is_ok());
    assert!(trace.read(3).is_ok());
    
    // Out of bounds operations should fail
    assert!(trace.write(4, FieldElement::from(1u64)).is_err());
    assert!(trace.write(100, FieldElement::from(1u64)).is_err());
    assert!(trace.read(4).is_err());
    assert!(trace.read(100).is_err());
}

#[test]
fn test_twist_protocol_small_trace() {
    let (prover_params, verifier_params) = setup_params(3); // 8 memory cells
    
    let mut trace = MemoryTrace::new(8);
    
    // Simple memory operations
    trace.write(0, FieldElement::from(10u64)).unwrap();
    trace.write(1, FieldElement::from(20u64)).unwrap();
    trace.read(0).unwrap();
    trace.write(2, FieldElement::from(30u64)).unwrap();
    trace.read(1).unwrap();
    trace.read(2).unwrap();
    
    let twist = Twist::new(&prover_params);
    
    // Generate proof
    let proof = twist.prove(&trace).unwrap();
    
    // Verify proof  
    let is_valid = twist.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Twist proof should be valid for correct memory trace");
}

#[test]
fn test_twist_protocol_empty_trace() {
    let (prover_params, verifier_params) = setup_params(2); // 4 memory cells
    
    let trace = MemoryTrace::new(4); // Empty trace
    
    let twist = Twist::new(&prover_params);
    
    // Should be able to prove empty trace
    let proof = twist.prove(&trace).unwrap();
    let is_valid = twist.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Empty memory trace should have valid proof");
}

#[test] 
fn test_twist_protocol_only_reads() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let mut trace = MemoryTrace::new(4);
    
    // Only read operations (should read zeros)
    trace.read(0).unwrap();
    trace.read(1).unwrap();
    trace.read(2).unwrap();
    trace.read(3).unwrap();
    
    let twist = Twist::new(&prover_params);
    
    let proof = twist.prove(&trace).unwrap();
    let is_valid = twist.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Read-only trace should have valid proof");
}

#[test]
fn test_twist_protocol_only_writes() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let mut trace = MemoryTrace::new(4);
    
    // Only write operations
    trace.write(0, FieldElement::from(1u64)).unwrap();
    trace.write(1, FieldElement::from(2u64)).unwrap();
    trace.write(2, FieldElement::from(3u64)).unwrap();
    trace.write(3, FieldElement::from(4u64)).unwrap();
    
    let twist = Twist::new(&prover_params);
    
    let proof = twist.prove(&trace).unwrap();
    let is_valid = twist.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Write-only trace should have valid proof");
}

#[test]
fn test_twist_protocol_repeated_operations() {
    let (prover_params, verifier_params) = setup_params(2);
    
    let mut trace = MemoryTrace::new(4);
    
    // Repeated operations on same address
    trace.write(0, FieldElement::from(100u64)).unwrap();
    trace.read(0).unwrap();
    trace.write(0, FieldElement::from(200u64)).unwrap(); // Overwrite
    trace.read(0).unwrap(); // Should read new value
    trace.write(0, FieldElement::from(300u64)).unwrap(); // Overwrite again
    trace.read(0).unwrap(); // Should read newest value
    
    let twist = Twist::new(&prover_params);
    
    let proof = twist.prove(&trace).unwrap();
    let is_valid = twist.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Trace with repeated operations should have valid proof");
}

#[test]
fn test_twist_protocol_max_operations() {
    let (prover_params, verifier_params) = setup_params(2); // 4 memory cells, max 16 operations
    
    let mut trace = MemoryTrace::new(4);
    
    // Fill up to just under the limit
    for i in 0..15 {
        let addr = i % 4;
        trace.write(addr, FieldElement::from((i + 1) as u64)).unwrap();
    }
    
    let twist = Twist::new(&prover_params);
    
    let proof = twist.prove(&trace).unwrap();
    let is_valid = twist.verify(&proof, &verifier_params).unwrap();
    assert!(is_valid, "Trace at operation limit should have valid proof");
}

#[test]
fn test_twist_protocol_exceeds_operations_limit() {
    let (prover_params, _) = setup_params(1); // 2 memory cells, max 8 operations
    
    let mut trace = MemoryTrace::new(2);
    
    // Exceed the operations limit
    for i in 0..10 {
        let addr = i % 2;
        trace.write(addr, FieldElement::from((i + 1) as u64)).unwrap();
    }
    
    let twist = Twist::new(&prover_params);
    
    // Should fail to generate proof due to too many operations
    let result = twist.prove(&trace);
    assert!(result.is_err(), "Should fail when exceeding operation limit");
}

#[test]
fn test_memory_operation_types() {
    use twist_and_shout::MemoryOp;
    
    let read_op = MemoryOp::Read { 
        address: 5, 
        value: FieldElement::from(42u64) 
    };
    let write_op = MemoryOp::Write { 
        address: 10, 
        value: FieldElement::from(100u64) 
    };
    
    // Test pattern matching
    match read_op {
        MemoryOp::Read { address, value } => {
            assert_eq!(address, 5);
            assert_eq!(value, FieldElement::from(42u64));
        }
        _ => panic!("Expected read operation"),
    }
    
    match write_op {
        MemoryOp::Write { address, value } => {
            assert_eq!(address, 10);
            assert_eq!(value, FieldElement::from(100u64));
        }
        _ => panic!("Expected write operation"),
    }
    
    // Test equality
    let read_op2 = MemoryOp::Read { 
        address: 5, 
        value: FieldElement::from(42u64) 
    };
    assert_eq!(read_op, read_op2);
    assert_ne!(read_op, write_op);
}