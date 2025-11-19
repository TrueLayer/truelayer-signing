using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;

namespace TrueLayer.Signing.Benchmarks;

/// <summary>
/// Benchmarks for signature verification operations.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class VerifierBenchmarks
{
    private string? _signature;
    private Verifier? _verifier;

    [GlobalSetup]
    public void Setup()
    {
        var privateKey = TestData.GetPrivateKey();
        var publicKey = TestData.GetPublicKey();
        var scenario = TestData.Scenarios.SmallPayment;

        _signature = Signer.SignWith(TestData.Kid, privateKey)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body)
            .Sign();

        _verifier = Verifier.VerifyWith(publicKey)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body);
    }

    [Benchmark(Description = "Verify Request")]
    public void VerifyRequest()
    {
        _verifier!.Verify(_signature!);
    }
}
