using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;

namespace TrueLayer.Signing.Benchmarks;

/// <summary>
/// Benchmarks for signing operations across different payload sizes and scenarios
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class SignerBenchmarks
{
    private Signer? _smallPaymentSigner;
    private Signer? _mediumMandateSigner;
    private Signer? _largeWebhookSigner;
    private Signer? _extraLargeBatchSigner;
    private Signer? _manyHeadersSigner;
    private Signer? _simpleGetSigner;

    [GlobalSetup]
    public void Setup()
    {
        var privateKey = TestData.GetPrivateKey();
        var kid = TestData.Kid;

        // Pre-build signers for each scenario
        _smallPaymentSigner = BuildSigner(privateKey, kid, TestData.Scenarios.SmallPayment);
        _mediumMandateSigner = BuildSigner(privateKey, kid, TestData.Scenarios.MediumMandate);
        _largeWebhookSigner = BuildSigner(privateKey, kid, TestData.Scenarios.LargeWebhook);
        _extraLargeBatchSigner = BuildSigner(privateKey, kid, TestData.Scenarios.ExtraLargeBatch);
        _manyHeadersSigner = BuildSigner(privateKey, kid, TestData.Scenarios.ManyHeaders);
        _simpleGetSigner = BuildSigner(privateKey, kid, TestData.Scenarios.SimpleGet);
    }

    private static Signer BuildSigner(System.Security.Cryptography.ECDsa key, string kid, TestData.RequestScenario scenario)
    {
        var signer = Signer.SignWith(kid, key)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Body(scenario.Body);

        foreach (var header in scenario.Headers)
        {
            signer.Header(header.Key, header.Value);
        }

        return signer;
    }

    [Benchmark(Description = "Sign Small Payment (250B)")]
    public string SignSmallPayment()
    {
        return _smallPaymentSigner!.Sign();
    }

    [Benchmark(Description = "Sign Medium Mandate (1KB)")]
    public string SignMediumMandate()
    {
        return _mediumMandateSigner!.Sign();
    }

    [Benchmark(Description = "Sign Large Webhook (10KB)")]
    public string SignLargeWebhook()
    {
        return _largeWebhookSigner!.Sign();
    }

    [Benchmark(Description = "Sign Extra Large Batch (100KB)")]
    public string SignExtraLargeBatch()
    {
        return _extraLargeBatchSigner!.Sign();
    }

    [Benchmark(Description = "Sign with Many Headers (20)")]
    public string SignManyHeaders()
    {
        return _manyHeadersSigner!.Sign();
    }

    [Benchmark(Description = "Sign Simple GET (no body)")]
    public string SignSimpleGet()
    {
        return _simpleGetSigner!.Sign();
    }

    /// <summary>
    /// Benchmark complete signing workflow including builder creation
    /// </summary>
    [Benchmark(Description = "Full Sign Workflow (Small Payment)")]
    public string FullSignWorkflow()
    {
        var scenario = TestData.Scenarios.SmallPayment;
        return Signer.SignWithPem(TestData.Kid, TestData.PrivateKeyPem)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body)
            .Sign();
    }

    /// <summary>
    /// Benchmark with JKU header
    /// </summary>
    [Benchmark(Description = "Sign with JKU")]
    public string SignWithJku()
    {
        var scenario = TestData.Scenarios.SmallPayment;
        return Signer.SignWith(TestData.Kid, TestData.GetPrivateKey())
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Body(scenario.Body)
            .Jku("https://webhooks.truelayer.com/.well-known/jwks")
            .Sign();
    }
}

/// <summary>
/// Benchmarks specifically focused on builder pattern operations
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
public class SignerBuilderBenchmarks
{
    private System.Security.Cryptography.ECDsa? _privateKey;

    [GlobalSetup]
    public void Setup()
    {
        _privateKey = TestData.GetPrivateKey();
    }

    [Benchmark(Description = "Create Signer Builder")]
    public Signer CreateBuilder()
    {
        return Signer.SignWith(TestData.Kid, _privateKey!);
    }

    [Benchmark(Description = "Builder with Method+Path")]
    public Signer BuilderMethodPath()
    {
        return Signer.SignWith(TestData.Kid, _privateKey!)
            .Method("POST")
            .Path("/payments");
    }

    [Benchmark(Description = "Builder with Single Header")]
    public Signer BuilderSingleHeader()
    {
        return Signer.SignWith(TestData.Kid, _privateKey!)
            .Method("POST")
            .Path("/payments")
            .Header("Idempotency-Key", "idemp-123");
    }

    [Benchmark(Description = "Builder with 5 Headers")]
    public Signer BuilderFiveHeaders()
    {
        return Signer.SignWith(TestData.Kid, _privateKey!)
            .Method("POST")
            .Path("/payments")
            .Header("Header-1", "value1")
            .Header("Header-2", "value2")
            .Header("Header-3", "value3")
            .Header("Header-4", "value4")
            .Header("Header-5", "value5");
    }

    [Benchmark(Description = "Builder with Body (1KB)")]
    public Signer BuilderWithBody()
    {
        return Signer.SignWith(TestData.Kid, _privateKey!)
            .Method("POST")
            .Path("/payments")
            .Body(TestData.Scenarios.MediumMandate.Body);
    }
}
