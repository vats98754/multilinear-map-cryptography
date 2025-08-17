# Benchmark Results Documentation

This document explains how to run, interpret, and optimize the Twist and Shout protocol benchmarks.

## Quick Start

```bash
# Fast benchmarks for development
cargo run --example comprehensive_benchmarks dev

# Quick benchmarks for regular testing  
cargo run --example comprehensive_benchmarks quick

# Full comprehensive benchmarks
cargo run --example comprehensive_benchmarks full
```

## Available Benchmark Modes

### Predefined Modes

| Mode | Log Sizes | Operations | Duration | Use Case |
|------|-----------|------------|----------|----------|
| `dev` | 4-5 | 32 | ~30 seconds | Development & quick validation |
| `quick` | 4-6 | 64 | ~2 minutes | Regular performance monitoring |
| default | 4-8 | 256 | ~5 minutes | Standard comprehensive analysis |
| `full` | 4-10 | 256 | ~15 minutes | Complete performance characterization |

### Custom Modes

```bash
# Custom parameter ranges
cargo run --example comprehensive_benchmarks custom \
  --min-log-size 4 --max-log-size 8 --operations 128

# Protocol-specific benchmarks
cargo run --example comprehensive_benchmarks twist-only --max-log-size 6
cargo run --example comprehensive_benchmarks shout-only --min-log-size 5
```

## Understanding Benchmark Results

### Result Table Columns

| Column | Description | Units | Interpretation |
|--------|-------------|-------|----------------|
| **Size** | Table/memory size (2^log_size) | entries | Larger = more memory/computation |
| **Setup(ms)** | Parameter generation time | milliseconds | One-time setup cost |
| **Prove(ms)** | Proof generation time | milliseconds | Main computational cost |
| **Verify(ms)** | Proof verification time | milliseconds | Verifier computational cost |
| **Proof(KB)** | Proof size estimate | kilobytes | Communication/storage cost |
| **Ops/sec** | Operations per second | operations/second | Throughput metric |

### Performance Characteristics

#### Expected Scaling Behavior

- **Setup Time**: O(n log n) where n is table size
- **Prove Time**: O(n log n) for both protocols  
- **Verify Time**: O(log n) - should remain relatively constant
- **Proof Size**: O(log n) - grows slowly with table size
- **Memory Usage**: O(n) - linear with table size

#### Protocol Comparison

**Twist Protocol (Memory Checking)**:
- Optimized for memory consistency proofs
- Better for applications with many memory reads/writes
- Generally faster verification for large memory traces

**Shout Protocol (Lookup Arguments)**:
- Optimized for table lookup proofs
- Better for applications with many table lookups
- More efficient proving for sparse lookups

## Performance Optimization Tips

### For Development

1. **Use `dev` mode** for rapid iteration
2. **Start with small log sizes** (4-6) during development
3. **Use protocol-specific modes** when working on one protocol

### For Production Analysis

1. **Use `quick` mode** for regular CI/performance monitoring
2. **Use `full` mode** for comprehensive analysis before releases
3. **Custom modes** for specific parameter ranges relevant to your use case

### Parameter Selection Guidelines

#### Log Size Selection
- **4-6**: Development and testing (16-64 entries)
- **6-8**: Typical application sizes (64-256 entries)  
- **8-10**: Large-scale applications (256-1024 entries)
- **10+**: Research/extreme scale (1K+ entries) - use with caution

#### Operations Count
- **Fewer operations** (32-64): Faster benchmarks, less accurate timing
- **More operations** (256-512): Slower benchmarks, more accurate timing
- **Dynamic scaling**: Automatically adjusts operations based on table size

## Interpreting Results

### Good Performance Indicators

- **Consistent scaling**: Times should grow predictably with size
- **Fast verification**: Verify time should be much less than prove time
- **Reasonable ratios**: Twist/Shout ratios should be between 0.5x-2x typically

### Performance Red Flags

- **Exponential scaling**: Times growing faster than O(n log n)
- **Slow verification**: Verify time comparable to prove time
- **Large proof sizes**: Proof sizes growing faster than O(log n)

### Example Analysis

```
Size    | Setup(ms) | Prove(ms) | Verify(ms) | Proof(KB) | Ops/sec
--------|-----------|-----------|------------|-----------|--------
16      | 109       | 15        | 111        | 0.50      | 251
32      | 207       | 54        | 110        | 0.62      | 148  
64      | 407       | 140       | 110        | 0.75      | 114
```

**Analysis**:
- ✅ Setup scales reasonably (roughly doubling with 2x size increase)
- ✅ Prove time scales well (less than 10x for 4x size increase)
- ✅ Verify time remains constant (good!)
- ✅ Proof size grows slowly (50% increase for 4x size)
- ⚠️ Ops/sec decreasing (expected due to algorithm complexity)

## Benchmark Architecture

### Test Data Generation

- **Memory operations**: Mix of 67% reads, 33% writes for realistic traces
- **Lookup operations**: Random indices with square number values
- **Operation scaling**: Dynamic adjustment based on table size for consistent runtime

### Measurement Methodology

- **Timing**: High-precision `std::time::Instant` measurements
- **Memory estimation**: Based on field element sizes and data structures
- **Proof size estimation**: Calculated from commitment and polynomial sizes
- **Multiple runs**: Each benchmark represents a single run (no averaging)

### Limitations

- **Single-threaded**: Benchmarks run on single core
- **Simulated data**: Uses synthetic rather than real application data
- **Estimation**: Proof sizes and memory usage are estimates
- **Platform dependent**: Results vary by hardware and system load

## Advanced Usage

### Continuous Integration

```bash
# Add to CI pipeline for performance regression detection
cargo run --example comprehensive_benchmarks quick > benchmark_results.txt
```

### Performance Profiling

```bash
# Use with profiling tools
perf record cargo run --example comprehensive_benchmarks dev
flamegraph target/debug/examples/comprehensive_benchmarks dev
```

### Comparison Analysis

```bash
# Before/after performance comparison
cargo run --example comprehensive_benchmarks custom --min-log-size 6 --max-log-size 8 --operations 100
# Make changes...
cargo run --example comprehensive_benchmarks custom --min-log-size 6 --max-log-size 8 --operations 100
```

## Troubleshooting

### Common Issues

1. **Very slow benchmarks**: Reduce log size range or use `dev` mode
2. **Inconsistent results**: System load variation - run multiple times
3. **Memory errors**: Reduce operations count for large log sizes
4. **Compilation errors**: Ensure all dependencies are installed

### Getting Help

- Check parameter ranges (log sizes 2-20, operations > 0)
- Use `help` command for usage information
- Start with `dev` mode to verify basic functionality
- Reduce parameters if encountering resource constraints

## Contributing

When adding new benchmark features:

1. **Maintain compatibility** with existing modes
2. **Add documentation** for new parameters or modes
3. **Test with various sizes** to ensure reasonable performance
4. **Update this documentation** with new features or insights