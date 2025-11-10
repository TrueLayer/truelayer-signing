# TrueLayer.Signing Benchmarks

Performance benchmarks for the TrueLayer signing library using [BenchmarkDotNet](https://benchmarkdotnet.org/).

## 🎯 What's Measured

### Signing Benchmarks (`SignerBenchmarks`)
- **Small Payment (250B)** - Typical payment request
- **Medium Mandate (1KB)** - Standard mandate creation
- **Large Webhook (10KB)** - Webhook payload
- **Extra Large Batch (100KB)** - Batch payment operations
- **Many Headers (20)** - Request with many custom headers
- **Simple GET** - GET request with no body
- **Full Workflow** - Complete sign operation including builder creation
- **Sign with JKU** - Signature with JSON Web Key URL

### Verification Benchmarks (`VerifierBenchmarks`)
- **Verify Small to Extra Large Payloads** - Same size variations as signing
- **Verify with Required Headers** - Verification with header validation
- **Full Verify Workflow** - Complete verification including builder creation

### Builder Pattern Benchmarks
- **SignerBuilderBenchmarks** - Measure builder pattern overhead
- **VerifierBuilderBenchmarks** - Measure verifier builder overhead

### Metadata Extraction (`VerifierMetadataBenchmarks`)
- **Extract Kid** - Extract key ID from signature
- **Extract Jku** - Extract JWK URL from signature

### JWS Verification Benchmarks (`JwsVerificationBenchmarks`)
Measures the performance impact of using native detached payload support vs manual JWS reconstruction:

- **JWS Verify - OLD (Manual Reconstruction)** - Baseline using Base64URL encoding + string concatenation
- **JWS Verify - NEW (Detached Payload)** - Optimized using native `JWT.DecodeBytes()` with detached payload parameter

**Results:**
- 34% reduction in memory allocations (45.32 KB → 30.07 KB per verification)
- 1.4% faster execution (660.7 μs → 651.7 μs per verification)
- 40% fewer Gen0 GC collections (4.88 → 2.93 per 1000 operations)

## 🚀 Running Benchmarks

### Prerequisites
```bash
cd csharp/benchmarks
dotnet restore
```

### Run All Benchmarks
```bash
dotnet run -c Release
```

### Run Specific Benchmark Suite
```bash
# Run only signing benchmarks
dotnet run -c Release -- signer

# Run only verification benchmarks
dotnet run -c Release -- verifier

# Run builder benchmarks
dotnet run -c Release -- signer-builder
dotnet run -c Release -- verifier-builder

# Run metadata extraction benchmarks
dotnet run -c Release -- verifier-metadata

# Run JWS verification benchmarks (detached payload optimization)
dotnet run -c Release -- jws
# or
dotnet run -c Release -- jws-verify
```

### Run Specific Benchmark Methods
```bash
# Filter by method name
dotnet run -c Release -- --filter "*SmallPayment*"

# Filter by multiple patterns
dotnet run -c Release -- --filter "*Sign* *Verify*"
```

### Advanced Options

#### Export Results
```bash
# Export to HTML
dotnet run -c Release -- --exporters html

# Export to CSV
dotnet run -c Release -- --exporters csv

# Export to JSON
dotnet run -c Release -- --exporters json

# Export multiple formats
dotnet run -c Release -- --exporters html csv json
```

#### Run with Different Configurations
```bash
# Run with different .NET runtimes (if installed)
dotnet run -c Release -- --runtimes net8.0 net9.0

# Run with memory diagnoser (default)
dotnet run -c Release -- --memory

# Run with specific job configuration
dotnet run -c Release -- --job short
```

#### Compare Branches
```bash
# Baseline on main branch
git checkout main
dotnet run -c Release -- --filter "*SignSmallPayment*" --exporters json

# Compare with feature branch
git checkout feature-branch
dotnet run -c Release -- --filter "*SignSmallPayment*" --exporters json --baseline

# BenchmarkDotNet will show comparison
```

## 📊 Understanding Results

### Key Metrics

- **Mean** - Average execution time
- **Error** - Half of 99.9% confidence interval
- **StdDev** - Standard deviation of all measurements
- **Rank** - Relative rank (1 = fastest)
- **Gen0/Gen1/Gen2** - Garbage collection counts per 1000 operations
- **Allocated** - Total allocated memory per operation

### Example Output
```
| Method                          | Mean      | Error    | StdDev   | Rank | Gen0   | Allocated |
|-------------------------------- |----------:|---------:|---------:|-----:|-------:|----------:|
| Sign Small Payment (250B)       | 524.3 μs  | 8.2 μs   | 7.7 μs   | 1    | 1.9531 | 8.12 KB   |
| Sign with Many Headers (20)     | 542.1 μs  | 9.1 μs   | 8.5 μs   | 2    | 2.9297 | 12.3 KB   |
| Sign Medium Mandate (1KB)       | 531.8 μs  | 7.4 μs   | 6.9 μs   | 3    | 2.9297 | 11.8 KB   |
```

### Performance Goals

**Signing Operations:**
- Small payloads (< 1KB): < 1ms average
- Medium payloads (1-10KB): < 2ms average
- Large payloads (10-100KB): < 5ms average

**Verification Operations:**
- Small payloads: < 2ms average
- Medium payloads: < 3ms average
- Large payloads: < 8ms average

**Memory Allocations:**
- Minimize Gen2 collections (should be 0 for typical operations)
- Keep allocations proportional to payload size
- Builder pattern should add minimal overhead (< 500 bytes)

## 🔍 Realistic Test Scenarios

All benchmarks use realistic TrueLayer API request patterns:

### Small Payment (250 bytes)
```json
{
  "amount_in_minor": 5000,
  "currency": "GBP",
  "payment_method": {
    "type": "bank_transfer",
    "provider_selection": {"type": "user_selected"}
  },
  "user": {"id": "user-123"}
}
```

### Medium Mandate (1KB)
Simulates mandate creation with typical metadata and configuration.

### Large Webhook (10KB)
Represents webhook payloads with multiple events or detailed data.

### Extra Large Batch (100KB)
Simulates batch operations with multiple payment records.

### Many Headers
Tests scenarios with 20 custom headers (CDN, tracing, etc.).

## 🛠️ Customizing Benchmarks

### Add New Scenario

1. Add scenario to `TestData.cs`:
```csharp
public static readonly RequestScenario MyScenario = new(
    Name: "My Scenario",
    Method: "POST",
    Path: "/my-endpoint",
    Headers: new Dictionary<string, string> { ["X-Custom"] = "value" },
    Body: "my payload"
);
```

2. Add benchmark method:
```csharp
[Benchmark(Description = "My Scenario")]
public string SignMyScenario()
{
    return _myScenarioSigner!.Sign();
}
```

3. Update `Setup()` to initialize the scenario.

## 📈 Continuous Performance Monitoring

To track performance over time:

```bash
# Run benchmarks and save baseline
dotnet run -c Release -- --exporters json --artifacts ./baseline

# Later, compare against baseline
dotnet run -c Release -- --exporters json --baseline ./baseline/results.json
```

Consider integrating with CI/CD:
- Run benchmarks on pull requests
- Fail if performance regresses > 10%
- Track trends over releases

## 🐛 Troubleshooting

### Benchmarks Run Slowly
Benchmarks are designed to be accurate, which takes time. Each benchmark:
- Runs warm-up iterations
- Runs multiple iterations for statistical significance
- Measures pilot runs to determine iteration count

Use `--job short` for faster (less accurate) results during development.

### High Memory Allocations
Check:
- Is GC pressure from payload size or library overhead?
- Compare `Allocated` across different payload sizes
- Look for unexpected Gen1/Gen2 collections

### Inconsistent Results
- Close other applications
- Run with `--job long` for more iterations
- Check for CPU throttling/thermal issues
- Ensure running in Release mode

## 📚 References

- [BenchmarkDotNet Documentation](https://benchmarkdotnet.org/articles/overview.html)
- [Interpreting Results](https://benchmarkdotnet.org/articles/guides/interpreting-results.html)
- [.NET Performance Best Practices](https://learn.microsoft.com/en-us/dotnet/framework/performance/)
