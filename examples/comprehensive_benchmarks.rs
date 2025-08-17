//! Comprehensive benchmark runner for Twist and Shout protocols.
//! 
//! Run with: cargo run --example comprehensive_benchmarks

use twist_and_shout::ProtocolBenchmarks;

fn main() {
    println!("🚀 Starting Comprehensive Performance Benchmarks");
    println!("=================================================\n");
    
    // Run the comprehensive benchmark suite
    ProtocolBenchmarks::run_comprehensive_benchmark();
    
    println!("\n✅ Comprehensive benchmarks completed!");
    println!("📊 Results show performance characteristics across different protocol sizes");
    println!("💡 Use these results to optimize protocol parameters for your use case");
}