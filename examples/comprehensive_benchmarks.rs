//! Comprehensive benchmark runner for Twist and Shout protocols.
//! 
//! This tool provides configurable performance benchmarks for both Twist and Shout protocols.
//! 
//! ## Usage Examples:
//! 
//! ```bash
//! # Quick benchmarks (log sizes 4-6, 64 operations)
//! cargo run --example comprehensive_benchmarks quick
//! 
//! # Full benchmarks (log sizes 4-10, 256 operations)  
//! cargo run --example comprehensive_benchmarks full
//! 
//! # Custom range and operations
//! cargo run --example comprehensive_benchmarks custom --min-log-size 4 --max-log-size 8 --operations 128
//! 
//! # Protocol-specific benchmarks
//! cargo run --example comprehensive_benchmarks twist-only --min-log-size 4 --max-log-size 6
//! cargo run --example comprehensive_benchmarks shout-only --max-log-size 8
//! 
//! # Development mode (very fast, minimal sizes)
//! cargo run --example comprehensive_benchmarks dev
//! 
//! # Help
//! cargo run --example comprehensive_benchmarks help
//! ```

use std::env;
use twist_and_shout::ProtocolBenchmarks;

fn main() {
    let args: Vec<String> = env::args().collect();
    
    if args.len() == 1 {
        run_default_benchmark();
        return;
    }
    
    let mode = &args[1];
    
    match mode.as_str() {
        "quick" => run_quick_benchmark(),
        "full" => run_full_benchmark(),
        "dev" => run_dev_benchmark(),
        "custom" => run_custom_benchmark(&args),
        "twist-only" => run_twist_only_benchmark(&args),
        "shout-only" => run_shout_only_benchmark(&args),
        "help" | "--help" | "-h" => print_help(),
        _ => {
            println!("❌ Unknown mode: {}", mode);
            println!("Use 'help' for usage information.");
            print_help();
            std::process::exit(1);
        }
    }
}

fn run_quick_benchmark() {
    println!("🚀 Quick Performance Benchmarks");
    println!("================================\n");
    println!("📝 Configuration: log sizes 4-6, 64 operations per size\n");
    ProtocolBenchmarks::run_quick_benchmark();
    print_completion_message();
}

fn run_full_benchmark() {
    println!("🚀 Full Comprehensive Performance Benchmarks");
    println!("==============================================\n");
    println!("📝 Configuration: log sizes 4-10, 256 operations per size\n");
    println!("⚠️  Warning: This may take several minutes to complete\n");
    ProtocolBenchmarks::run_comprehensive_benchmark_with_params(4, 10, 256);
    print_completion_message();
}

fn run_default_benchmark() {
    println!("🚀 Default Comprehensive Performance Benchmarks");
    println!("================================================\n");
    println!("📝 Configuration: log sizes 4-8, 256 operations per size\n");
    ProtocolBenchmarks::run_comprehensive_benchmark();
    print_completion_message();
}

fn run_dev_benchmark() {
    println!("🚀 Development Mode Benchmarks");
    println!("===============================\n");
    println!("📝 Configuration: log sizes 4-5, 32 operations (very fast)\n");
    ProtocolBenchmarks::run_comprehensive_benchmark_with_params(4, 5, 32);
    print_completion_message();
}

fn run_custom_benchmark(args: &[String]) {
    let mut min_log_size = 4;
    let mut max_log_size = 8;
    let mut operations = 256;
    
    // Parse custom arguments
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--min-log-size" => {
                if i + 1 < args.len() {
                    min_log_size = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("❌ Invalid min-log-size value: {}", args[i + 1]);
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            "--max-log-size" => {
                if i + 1 < args.len() {
                    max_log_size = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("❌ Invalid max-log-size value: {}", args[i + 1]);
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            "--operations" => {
                if i + 1 < args.len() {
                    operations = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("❌ Invalid operations value: {}", args[i + 1]);
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            _ => {
                eprintln!("❌ Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }
    
    // Validation
    if min_log_size > max_log_size {
        eprintln!("❌ min-log-size ({}) cannot be greater than max-log-size ({})", min_log_size, max_log_size);
        std::process::exit(1);
    }
    
    if min_log_size < 2 || max_log_size > 20 {
        eprintln!("❌ Log sizes must be between 2 and 20 (table sizes 4 to 1M)");
        std::process::exit(1);
    }
    
    println!("🚀 Custom Performance Benchmarks");
    println!("=================================\n");
    println!("📝 Configuration: log sizes {}-{}, {} operations per size\n", min_log_size, max_log_size, operations);
    
    ProtocolBenchmarks::run_comprehensive_benchmark_with_params(min_log_size, max_log_size, operations);
    print_completion_message();
}

fn run_twist_only_benchmark(args: &[String]) {
    let mut min_log_size = 4;
    let mut max_log_size = 8;
    let mut operations = 256;
    
    // Parse arguments (same logic as custom)
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--min-log-size" => {
                if i + 1 < args.len() {
                    min_log_size = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("❌ Invalid min-log-size value: {}", args[i + 1]);
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            "--max-log-size" => {
                if i + 1 < args.len() {
                    max_log_size = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("❌ Invalid max-log-size value: {}", args[i + 1]);
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            "--operations" => {
                if i + 1 < args.len() {
                    operations = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("❌ Invalid operations value: {}", args[i + 1]);
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            _ => {
                eprintln!("❌ Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }
    
    println!("🚀 Twist Protocol Only - Performance Benchmarks");
    println!("================================================\n");
    println!("📝 Configuration: log sizes {}-{}, {} operations per size\n", min_log_size, max_log_size, operations);
    
    let twist_results = ProtocolBenchmarks::benchmark_twist_scaling_range(min_log_size, max_log_size);
    ProtocolBenchmarks::print_scaling_results("Twist", &twist_results);
    print_completion_message();
}

fn run_shout_only_benchmark(args: &[String]) {
    let mut min_log_size = 4;
    let mut max_log_size = 8;
    let mut operations = 256;
    
    // Parse arguments (same logic as custom)
    let mut i = 2;
    while i < args.len() {
        match args[i].as_str() {
            "--min-log-size" => {
                if i + 1 < args.len() {
                    min_log_size = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("❌ Invalid min-log-size value: {}", args[i + 1]);
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            "--max-log-size" => {
                if i + 1 < args.len() {
                    max_log_size = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("❌ Invalid max-log-size value: {}", args[i + 1]);
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            "--operations" => {
                if i + 1 < args.len() {
                    operations = args[i + 1].parse().unwrap_or_else(|_| {
                        eprintln!("❌ Invalid operations value: {}", args[i + 1]);
                        std::process::exit(1);
                    });
                    i += 1;
                }
            }
            _ => {
                eprintln!("❌ Unknown argument: {}", args[i]);
                std::process::exit(1);
            }
        }
        i += 1;
    }
    
    println!("🚀 Shout Protocol Only - Performance Benchmarks");
    println!("=================================================\n");
    println!("📝 Configuration: log sizes {}-{}, {} operations per size\n", min_log_size, max_log_size, operations);
    
    let shout_results = ProtocolBenchmarks::benchmark_shout_scaling_range(min_log_size, max_log_size);
    ProtocolBenchmarks::print_scaling_results("Shout", &shout_results);
    print_completion_message();
}

fn print_help() {
    println!("🚀 Twist and Shout Protocol Benchmarks");
    println!("========================================\n");
    println!("USAGE:");
    println!("    cargo run --example comprehensive_benchmarks [MODE] [OPTIONS]\n");
    println!("MODES:");
    println!("    quick          Fast benchmarks (log sizes 4-6, 64 operations)");
    println!("    full           Full benchmarks (log sizes 4-10, 256 operations)");
    println!("    dev            Development mode (log sizes 4-5, 32 operations)");
    println!("    custom         Custom parameters (use with --min-log-size, --max-log-size, --operations)");
    println!("    twist-only     Run only Twist protocol benchmarks");
    println!("    shout-only     Run only Shout protocol benchmarks");
    println!("    help           Show this help message\n");
    println!("OPTIONS:");
    println!("    --min-log-size N    Minimum log₂(table size) (default: 4, min: 2, max: 20)");
    println!("    --max-log-size N    Maximum log₂(table size) (default: 8, min: 2, max: 20)");
    println!("    --operations N      Number of operations per table size (default: 256)\n");
    println!("EXAMPLES:");
    println!("    cargo run --example comprehensive_benchmarks quick");
    println!("    cargo run --example comprehensive_benchmarks custom --min-log-size 4 --max-log-size 8 --operations 128");
    println!("    cargo run --example comprehensive_benchmarks twist-only --max-log-size 6");
    println!("    cargo run --example comprehensive_benchmarks shout-only --min-log-size 5 --max-log-size 7\n");
    println!("PERFORMANCE TIPS:");
    println!("    - Use 'dev' mode for quick testing during development");
    println!("    - Use 'quick' mode for regular performance monitoring");
    println!("    - Use 'full' mode for comprehensive analysis (takes longer)");
    println!("    - Larger log sizes (>10) can take significant time");
    println!("    - More operations provide more accurate timings but take longer");
}

fn print_completion_message() {
    println!("\n✅ Benchmarks completed!");
    println!("📊 Results show performance characteristics across different protocol sizes");
    println!("💡 Use these results to optimize protocol parameters for your use case");
    println!("\n📖 For more information, see BENCHMARK_RESULTS.md");
    println!("🔧 Run with 'help' to see all available options");
}