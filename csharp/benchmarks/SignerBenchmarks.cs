using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;

namespace TrueLayer.Signing.Benchmarks;

/// <summary>
/// Benchmarks for signing operations.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class SignerBenchmarks
{
    private Signer? _signer;

    [GlobalSetup]
    public void Setup()
    {
        var privateKey = TestData.GetPrivateKey();
        var scenario = TestData.Scenarios.SmallPayment;

        _signer = Signer.SignWith(TestData.Kid, privateKey)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body);
    }

    [Benchmark(Description = "Sign Request")]
    public string SignRequest()
    {
        return _signer!.Sign();
    }
}
