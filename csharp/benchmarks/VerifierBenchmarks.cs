using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;

namespace TrueLayer.Signing.Benchmarks;

/// <summary>
/// Benchmarks for signature verification operations.
/// Compares the builder-based Verifier API with the optimized VerifierSpan API (NET8+).
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class VerifierBenchmarks
{
    private string _signature = null!;
    private byte[] _publicKeyPemBytes = null!;
    private string _method = null!;
    private string _path = null!;
    private KeyValuePair<string, byte[]>[] _headersBytes = null!;
    private byte[] _bodyBytes = null!;

    [Params("SmallPayment", "MediumMandate", "LargeWebhook")]
    public string Scenario { get; set; } = "SmallPayment";

    [GlobalSetup]
    public void Setup()
    {
        var privateKey = TestData.GetPrivateKey();
        var scenario = GetScenario(Scenario);

        _signature = Signer.SignWith(TestData.Kid, privateKey)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body)
            .Sign();

        // Setup for span-based VerifierSpan
        _publicKeyPemBytes = Encoding.UTF8.GetBytes(TestData.PublicKeyPem);
        _method = scenario.Method;
        _path = scenario.Path;
        _headersBytes = scenario.Headers
            .Select(h => new KeyValuePair<string, byte[]>(h.Key, Encoding.UTF8.GetBytes(h.Value)))
            .ToArray();
        _bodyBytes = Encoding.UTF8.GetBytes(scenario.Body);
    }

    private static TestData.RequestScenario GetScenario(string name) => name switch
    {
        "SmallPayment" => TestData.Scenarios.SmallPayment,
        "MediumMandate" => TestData.Scenarios.MediumMandate,
        "LargeWebhook" => TestData.Scenarios.LargeWebhook,
        _ => TestData.Scenarios.SmallPayment
    };

    [Benchmark(Baseline = true, Description = "Verifier (with PEM parsing)")]
    public void VerifierBuilderWithPemParsing()
    {
        var scenario = GetScenario(Scenario);
        using var key = ECDsa.Create();
        key.ImportFromPem(TestData.PublicKeyPem);

        Verifier.VerifyWith(key)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body)
            .Verify(_signature);
    }

    [Benchmark(Description = "VerifierSpan (with PEM parsing)")]
    public void VerifierSpanWithPemParsing()
    {
        VerifierSpan.VerifyWithPem(
            _publicKeyPemBytes,
            _method,
            _path,
            _headersBytes,
            _bodyBytes,
            _signature
        );
    }
}
