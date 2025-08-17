//! Comprehensive benchmark runner for Twist and Shout protocols.
//! 
//! Run with: cargo run --example comprehensive_benchmarks [quick|full]

use std::env;
use twist_and_shout::ProtocolBenchmarks;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mode = args.get(1).map(|s| s.as_str()).unwrap_or("default");
    
    match mode {
        "quick" => {
            println!("🚀 Quick Performance Benchmarks");
            println!("================================\n");
            ProtocolBenchmarks::run_quick_benchmark();
        }
        "full" => {
            println!("🚀 Full Comprehensive Performance Benchmarks");
            println!("==============================================\n");
            ProtocolBenchmarks::run_comprehensive_benchmark_with_params(4, 10, 256);
        }
        _ => {
            println!("🚀 Default Comprehensive Performance Benchmarks");
            println!("================================================\n");
            ProtocolBenchmarks::run_comprehensive_benchmark();
        }
    }
    
    println!("\n✅ Benchmarks completed!");
    println!("📊 Results show performance characteristics across different protocol sizes");
    println!("💡 Use these results to optimize protocol parameters for your use case");
    println!("\nAvailable modes:");
    println!("  cargo run --example comprehensive_benchmarks quick  # Fast benchmarks (log sizes 4-6)");
    println!("  cargo run --example comprehensive_benchmarks full   # Full benchmarks (log sizes 4-10)");
    println!("  cargo run --example comprehensive_benchmarks        # Default benchmarks (log sizes 4-8)");
}