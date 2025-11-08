using BenchmarkDotNet.Configs;
using BenchmarkDotNet.Running;
using TrueLayer.Signing.Benchmarks;

// Configure BenchmarkDotNet
var config = DefaultConfig.Instance
    .WithOptions(ConfigOptions.DisableOptimizationsValidator);

// Run all benchmarks or specific ones based on args
if (args.Length > 0)
{
    switch (args[0].ToLowerInvariant())
    {
        case "signer":
            BenchmarkRunner.Run<SignerBenchmarks>(config);
            break;
        case "signer-builder":
            BenchmarkRunner.Run<SignerBuilderBenchmarks>(config);
            break;
        case "verifier":
            BenchmarkRunner.Run<VerifierBenchmarks>(config);
            break;
        case "verifier-builder":
            BenchmarkRunner.Run<VerifierBuilderBenchmarks>(config);
            break;
        case "verifier-metadata":
            BenchmarkRunner.Run<VerifierMetadataBenchmarks>(config);
            break;
        case "internal":
        case "performance":
            BenchmarkRunner.Run<InternalPerformanceBenchmarks>(config);
            break;
        case "impact":
        case "optimization":
            BenchmarkRunner.Run<OptimizationImpactBenchmarks>(config);
            break;
        case "regression":
            BenchmarkRunner.Run<OptimizationRegressionTests>(config);
            break;
        case "all":
        default:
            BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, config);
            break;
    }
}
else
{
    // Interactive mode - let user choose
    BenchmarkSwitcher.FromAssembly(typeof(Program).Assembly).Run(args, config);
}
