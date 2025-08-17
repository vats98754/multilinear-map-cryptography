//! Benchmarking utilities for Twist and Shout protocols.

use crate::utils::{FieldElement, setup_params};
use crate::{Twist, Shout, MemoryTrace, LookupTable};
use std::time::{Duration, Instant};

/// Benchmark results for protocol operations
#[derive(Debug, Clone)]
pub struct BenchmarkResults {
    /// Setup time
    pub setup_time: Duration,
    /// Proving time
    pub prove_time: Duration,
    /// Verification time
    pub verify_time: Duration,
    /// Proof size in bytes (estimated)
    pub proof_size: usize,
    /// Number of operations processed
    pub num_operations: usize,
    /// Memory usage in bytes (estimated)
    pub memory_usage: usize,
}

impl BenchmarkResults {
    /// Calculate operations per second for proving
    pub fn prove_ops_per_second(&self) -> f64 {
        self.num_operations as f64 / self.prove_time.as_secs_f64()
    }
    
    /// Calculate operations per second for verification
    pub fn verify_ops_per_second(&self) -> f64 {
        self.num_operations as f64 / self.verify_time.as_secs_f64()
    }
    
    /// Get total time for complete protocol
    pub fn total_time(&self) -> Duration {
        self.setup_time + self.prove_time + self.verify_time
    }
}

/// Comprehensive benchmark suite for Twist and Shout protocols
pub struct ProtocolBenchmarks;

impl ProtocolBenchmarks {
    /// Benchmark Twist protocol with various memory sizes
    pub fn benchmark_twist_scaling() -> Vec<(usize, BenchmarkResults)> {
        Self::benchmark_twist_scaling_range(4, 8) // Good balance of coverage and speed
    }
    
    /// Benchmark Twist protocol with configurable size range
    pub fn benchmark_twist_scaling_range(min_log_size: usize, max_log_size: usize) -> Vec<(usize, BenchmarkResults)> {
        let mut results = Vec::new();
        
        // Test different memory sizes (powers of 2)
        for log_size in min_log_size..=max_log_size {
            let memory_size = 1 << log_size;
            // Dynamic operation scaling: more operations for smaller sizes, fewer for larger
            let num_operations = if memory_size <= 64 {
                memory_size / 2  // 50% utilization for small sizes
            } else if memory_size <= 512 {
                memory_size / 4  // 25% utilization for medium sizes  
            } else {
                memory_size / 8  // 12.5% utilization for large sizes
            };
            
            println!("  Testing Twist with memory size: {} (2^{}), operations: {}", 
                     memory_size, log_size, num_operations);
            let bench_result = Self::benchmark_twist_single(log_size, num_operations);
            results.push((memory_size, bench_result));
        }
        
        results
    }
    
    /// Benchmark a single Twist protocol instance
    pub fn benchmark_twist_single(log_size: usize, num_operations: usize) -> BenchmarkResults {
        // Setup phase
        let setup_start = Instant::now();
        let (prover_params, verifier_params) = setup_params(log_size);
        let twist = Twist::new(&prover_params);
        let setup_time = setup_start.elapsed();
        
        // Create memory trace
        let memory_size = 1 << log_size;
        let mut trace = MemoryTrace::new(memory_size);
        
        // Populate with operations (mix of reads and writes)
        for i in 0..num_operations {
            if i % 3 == 0 {
                // Write operation
                let addr = i % memory_size;
                let value = FieldElement::from((i * 42) as u64);
                trace.write(addr, value).unwrap();
            } else {
                // Read operation
                let addr = (i / 2) % memory_size;
                trace.read(addr).unwrap();
            }
        }
        
        // Proving phase
        let prove_start = Instant::now();
        let proof = twist.prove(&trace).unwrap();
        let prove_time = prove_start.elapsed();
        
        // Verification phase
        let verify_start = Instant::now();
        let is_valid = twist.verify(&proof, &verifier_params).unwrap();
        let verify_time = verify_start.elapsed();
        
        assert!(is_valid, "Proof verification failed");
        
        // Estimate proof size and memory usage
        let proof_size = Self::estimate_twist_proof_size(&proof);
        let memory_usage = Self::estimate_memory_usage(memory_size, num_operations);
        
        BenchmarkResults {
            setup_time,
            prove_time,
            verify_time,
            proof_size,
            num_operations: trace.operations.len(),
            memory_usage,
        }
    }
    
    /// Benchmark Shout protocol with various table sizes
    pub fn benchmark_shout_scaling() -> Vec<(usize, BenchmarkResults)> {
        Self::benchmark_shout_scaling_range(4, 8) // Good balance of coverage and speed
    }
    
    /// Benchmark Shout protocol with configurable size range
    pub fn benchmark_shout_scaling_range(min_log_size: usize, max_log_size: usize) -> Vec<(usize, BenchmarkResults)> {
        let mut results = Vec::new();
        
        // Test different table sizes (powers of 2)
        for log_size in min_log_size..=max_log_size {
            let table_size = 1 << log_size;
            // Dynamic operation scaling: more lookups for smaller sizes, fewer for larger
            let num_lookups = if table_size <= 64 {
                table_size / 2  // 50% utilization for small sizes
            } else if table_size <= 512 {
                table_size / 4  // 25% utilization for medium sizes
            } else {
                table_size / 8  // 12.5% utilization for large sizes
            };
            
            println!("  Testing Shout with table size: {} (2^{}), lookups: {}", 
                     table_size, log_size, num_lookups);
            let bench_result = Self::benchmark_shout_single(log_size, num_lookups);
            results.push((table_size, bench_result));
        }
        
        results
    }
    
    /// Benchmark a single Shout protocol instance
    pub fn benchmark_shout_single(log_size: usize, num_lookups: usize) -> BenchmarkResults {
        // Setup phase
        let setup_start = Instant::now();
        let (prover_params, verifier_params) = setup_params(log_size);
        let shout = Shout::new(&prover_params);
        let setup_time = setup_start.elapsed();
        
        // Create lookup table
        let table_size = 1 << log_size;
        let entries: Vec<FieldElement> = (0..table_size)
            .map(|i| FieldElement::from((i * i) as u64)) // Square numbers
            .collect();
        
        let mut table = LookupTable::new(entries);
        
        // Perform lookups
        for i in 0..num_lookups {
            let index = i % table_size;
            table.lookup(index).unwrap();
        }
        
        // Proving phase
        let prove_start = Instant::now();
        let proof = shout.prove(&table).unwrap();
        let prove_time = prove_start.elapsed();
        
        // Verification phase
        let verify_start = Instant::now();
        let is_valid = shout.verify(&proof, &verifier_params).unwrap();
        let verify_time = verify_start.elapsed();
        
        assert!(is_valid, "Proof verification failed");
        
        // Estimate proof size and memory usage
        let proof_size = Self::estimate_shout_proof_size(&proof);
        let memory_usage = Self::estimate_memory_usage(table_size, num_lookups);
        
        BenchmarkResults {
            setup_time,
            prove_time,
            verify_time,
            proof_size,
            num_operations: table.lookups.len(),
            memory_usage,
        }
    }
    
    /// Performance comparison between Twist and Shout
    pub fn comparative_benchmark(log_size: usize, num_operations: usize) -> (BenchmarkResults, BenchmarkResults) {
        let twist_results = Self::benchmark_twist_single(log_size, num_operations);
        let shout_results = Self::benchmark_shout_single(log_size, num_operations);
        
        (twist_results, shout_results)
    }
    
    /// Run comprehensive benchmark suite and print results
    pub fn run_comprehensive_benchmark() {
        Self::run_comprehensive_benchmark_with_params(4, 8, 256)
    }
    
    /// Run comprehensive benchmark suite with configurable parameters
    pub fn run_comprehensive_benchmark_with_params(min_log_size: usize, max_log_size: usize, num_ops: usize) {
        println!("🚀 Twist and Shout Protocol Benchmark Suite");
        println!("============================================\n");
        
        // Twist scaling benchmarks
        println!("📊 Twist Protocol Scaling Analysis:");
        let twist_results = Self::benchmark_twist_scaling_range(min_log_size, max_log_size);
        Self::print_scaling_results("Twist", &twist_results);
        
        println!("\n📊 Shout Protocol Scaling Analysis:");
        let shout_results = Self::benchmark_shout_scaling_range(min_log_size, max_log_size);
        Self::print_scaling_results("Shout", &shout_results);
        
        // Comparative analysis at a fixed size
        let compare_log_size = (min_log_size + max_log_size) / 2;
        let compare_table_size = 1 << compare_log_size;
        println!("\n🔄 Comparative Analysis (Memory/Table Size: {}):", compare_table_size);
        let (twist_comp, shout_comp) = Self::comparative_benchmark(compare_log_size, num_ops);
        Self::print_comparative_results(&twist_comp, &shout_comp);
    }
    
    /// Run quick benchmark suite for development/testing
    pub fn run_quick_benchmark() {
        Self::run_comprehensive_benchmark_with_params(4, 6, 64)
    }
    
    /// Run ultra-fast benchmark for development (minimal sizes)
    pub fn run_dev_benchmark() {
        Self::run_comprehensive_benchmark_with_params(4, 5, 32)
    }
    
    /// Run optimized benchmark with dynamic operation scaling
    pub fn run_optimized_benchmark(min_log_size: usize, max_log_size: usize) {
        println!("🚀 Optimized Twist and Shout Protocol Benchmark Suite");
        println!("======================================================\n");
        
        // Dynamic operation scaling: fewer operations for larger sizes
        for log_size in min_log_size..=max_log_size {
            let table_size = 1 << log_size;
            // Scale operations inversely with table size for consistent runtime
            let num_operations = std::cmp::max(32, 512 / (1 << (log_size - 4)));
            
            println!("📊 Protocol Comparison at size {} (2^{}) with {} operations:", 
                     table_size, log_size, num_operations);
            
            let (twist_result, shout_result) = Self::comparative_benchmark(log_size, num_operations);
            
            println!("Protocol | Prove(ms) | Verify(ms) | Proof(KB) | Ops/sec | Memory(KB)");
            println!("---------|-----------|------------|-----------|---------|----------");
            println!(
                "Twist    | {:.2}      | {:.2}       | {:.2}      | {:.0}     | {:.1}",
                twist_result.prove_time.as_millis(),
                twist_result.verify_time.as_millis(),
                twist_result.proof_size as f64 / 1024.0,
                twist_result.prove_ops_per_second(),
                twist_result.memory_usage as f64 / 1024.0
            );
            println!(
                "Shout    | {:.2}      | {:.2}       | {:.2}      | {:.0}     | {:.1}",
                shout_result.prove_time.as_millis(),
                shout_result.verify_time.as_millis(),
                shout_result.proof_size as f64 / 1024.0,
                shout_result.prove_ops_per_second(),
                shout_result.memory_usage as f64 / 1024.0
            );
            println!();
        }
    }
    
    /// Print scaling benchmark results
    pub fn print_scaling_results(protocol: &str, results: &[(usize, BenchmarkResults)]) {
        println!("Size\t| Setup(ms)\t| Prove(ms)\t| Verify(ms)\t| Proof(KB)\t| Ops/sec");
        println!("--------|---------------|---------------|---------------|---------------|--------");
        
        for (size, result) in results {
            println!(
                "{}\t| {:.2}\t\t| {:.2}\t\t| {:.2}\t\t| {:.2}\t\t| {:.0}",
                size,
                result.setup_time.as_millis(),
                result.prove_time.as_millis(),
                result.verify_time.as_millis(),
                result.proof_size as f64 / 1024.0,
                result.prove_ops_per_second()
            );
        }
    }
    
    /// Print comparative benchmark results
    fn print_comparative_results(twist: &BenchmarkResults, shout: &BenchmarkResults) {
        println!("Protocol | Prove(ms) | Verify(ms) | Proof(KB) | Ops/sec | Total(ms)");
        println!("---------|-----------|------------|-----------|---------|----------");
        println!(
            "Twist    | {:.2}      | {:.2}       | {:.2}      | {:.0}     | {:.2}",
            twist.prove_time.as_millis(),
            twist.verify_time.as_millis(),
            twist.proof_size as f64 / 1024.0,
            twist.prove_ops_per_second(),
            twist.total_time().as_millis()
        );
        println!(
            "Shout    | {:.2}      | {:.2}       | {:.2}      | {:.0}     | {:.2}",
            shout.prove_time.as_millis(),
            shout.verify_time.as_millis(),
            shout.proof_size as f64 / 1024.0,
            shout.prove_ops_per_second(),
            shout.total_time().as_millis()
        );
        
        // Performance ratios
        let prove_ratio = twist.prove_time.as_millis() as f64 / shout.prove_time.as_millis() as f64;
        let verify_ratio = twist.verify_time.as_millis() as f64 / shout.verify_time.as_millis() as f64;
        
        println!("\n📈 Performance Ratios (Twist/Shout):");
        println!("Proving: {:.2}x, Verification: {:.2}x", prove_ratio, verify_ratio);
    }
    
    /// Estimate proof size for Twist protocol
    fn estimate_twist_proof_size(proof: &crate::twist::TwistProof) -> usize {
        // Rough estimation based on typical sizes
        let commitment_size = 64; // G1 point in compressed form
        let sumcheck_size = proof.consistency_proof.round_polynomials.len() * 128; // Polynomials
        let opening_size = proof.opening_proofs.len() * 64; // G1 proofs
        
        2 * commitment_size + sumcheck_size + opening_size
    }
    
    /// Estimate proof size for Shout protocol
    fn estimate_shout_proof_size(proof: &crate::shout::ShoutProof) -> usize {
        // Rough estimation based on typical sizes
        let commitment_size = 64; // G1 point in compressed form
        let sumcheck_size = proof.lookup_proof.round_polynomials.len() * 128; // Polynomials
        let opening_size = proof.opening_proofs.len() * 64; // G1 proofs
        
        2 * commitment_size + sumcheck_size + opening_size
    }
    
    /// Estimate memory usage
    fn estimate_memory_usage(table_size: usize, num_operations: usize) -> usize {
        // Field elements (32 bytes each) + overhead
        let field_size = 32;
        let table_memory = table_size * field_size;
        let operations_memory = num_operations * field_size * 3; // address, value, type
        
        table_memory + operations_memory
    }
}

/// Simple benchmarking placeholder - will be expanded when protocols are complete
pub fn benchmark_setup(log_size: usize) -> (usize, usize) {
    let (prover_params, verifier_params) = setup_params(log_size);
    (prover_params.max_operations, verifier_params.max_operations)
}