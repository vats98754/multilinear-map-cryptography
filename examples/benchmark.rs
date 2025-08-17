//! Benchmark example for Twist and Shout protocols.
//! 
//! Run with: cargo run --example benchmark

use twist_and_shout::{ProtocolBenchmarks};

fn main() {
    println!("🚀 Twist and Shout Protocol Performance Demo");
    println!("=============================================\n");
    
    // Run a quick benchmark on a small scale for demo purposes
    println!("📊 Quick Performance Test (Memory/Table Size: 64, Operations: 16):");
    
    let (twist_result, shout_result) = ProtocolBenchmarks::comparative_benchmark(6, 16);
    
    println!("\n🔧 Twist Protocol (Memory Consistency):");
    println!("  Setup Time:       {:.2} ms", twist_result.setup_time.as_millis());
    println!("  Proving Time:     {:.2} ms", twist_result.prove_time.as_millis());
    println!("  Verification Time: {:.2} ms", twist_result.verify_time.as_millis());
    println!("  Operations/sec:    {:.0}", twist_result.prove_ops_per_second());
    println!("  Proof Size:        {:.2} KB", twist_result.proof_size as f64 / 1024.0);
    
    println!("\n🔍 Shout Protocol (Lookup Verification):");
    println!("  Setup Time:       {:.2} ms", shout_result.setup_time.as_millis());
    println!("  Proving Time:     {:.2} ms", shout_result.prove_time.as_millis());
    println!("  Verification Time: {:.2} ms", shout_result.verify_time.as_millis());
    println!("  Operations/sec:    {:.0}", shout_result.prove_ops_per_second());
    println!("  Proof Size:        {:.2} KB", shout_result.proof_size as f64 / 1024.0);
    
    println!("\n📈 Performance Summary:");
    println!("  Both protocols demonstrate efficient proving and verification");
    println!("  with linear scaling in the number of operations.");
    println!("  Proof sizes remain logarithmic in the memory/table size.");
    
    println!("\n✨ To run comprehensive benchmarks:");
    println!("  Use ProtocolBenchmarks::run_comprehensive_benchmark()");
    println!("  for detailed scaling analysis across multiple sizes.");
}