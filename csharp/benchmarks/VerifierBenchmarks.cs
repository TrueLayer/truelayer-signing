using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;

namespace TrueLayer.Signing.Benchmarks;

/// <summary>
/// Benchmarks for signature verification operations
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class VerifierBenchmarks
{
    private string? _smallPaymentSignature;
    private string? _mediumMandateSignature;
    private string? _largeWebhookSignature;
    private string? _extraLargeBatchSignature;
    private string? _manyHeadersSignature;
    private string? _simpleGetSignature;

    private Verifier? _smallPaymentVerifier;
    private Verifier? _mediumMandateVerifier;
    private Verifier? _largeWebhookVerifier;
    private Verifier? _extraLargeBatchVerifier;
    private Verifier? _manyHeadersVerifier;
    private Verifier? _simpleGetVerifier;

    [GlobalSetup]
    public void Setup()
    {
        var privateKey = TestData.GetPrivateKey();
        var publicKey = TestData.GetPublicKey();
        var kid = TestData.Kid;

        // Generate signatures for each scenario
        _smallPaymentSignature = SignScenario(privateKey, kid, TestData.Scenarios.SmallPayment);
        _mediumMandateSignature = SignScenario(privateKey, kid, TestData.Scenarios.MediumMandate);
        _largeWebhookSignature = SignScenario(privateKey, kid, TestData.Scenarios.LargeWebhook);
        _extraLargeBatchSignature = SignScenario(privateKey, kid, TestData.Scenarios.ExtraLargeBatch);
        _manyHeadersSignature = SignScenario(privateKey, kid, TestData.Scenarios.ManyHeaders);
        _simpleGetSignature = SignScenario(privateKey, kid, TestData.Scenarios.SimpleGet);

        // Pre-build verifiers for each scenario
        _smallPaymentVerifier = BuildVerifier(publicKey, TestData.Scenarios.SmallPayment);
        _mediumMandateVerifier = BuildVerifier(publicKey, TestData.Scenarios.MediumMandate);
        _largeWebhookVerifier = BuildVerifier(publicKey, TestData.Scenarios.LargeWebhook);
        _extraLargeBatchVerifier = BuildVerifier(publicKey, TestData.Scenarios.ExtraLargeBatch);
        _manyHeadersVerifier = BuildVerifier(publicKey, TestData.Scenarios.ManyHeaders);
        _simpleGetVerifier = BuildVerifier(publicKey, TestData.Scenarios.SimpleGet);
    }

    private static string SignScenario(System.Security.Cryptography.ECDsa key, string kid, TestData.RequestScenario scenario)
    {
        var signer = Signer.SignWith(kid, key)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Body(scenario.Body);

        foreach (var header in scenario.Headers)
        {
            signer.Header(header.Key, header.Value);
        }

        return signer.Sign();
    }

    private static Verifier BuildVerifier(System.Security.Cryptography.ECDsa key, TestData.RequestScenario scenario)
    {
        var verifier = Verifier.VerifyWith(key)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Body(scenario.Body);

        foreach (var header in scenario.Headers)
        {
            verifier.Header(header.Key, header.Value);
        }

        return verifier;
    }

    [Benchmark(Description = "Verify Small Payment (250B)")]
    public void VerifySmallPayment()
    {
        _smallPaymentVerifier!.Verify(_smallPaymentSignature!);
    }

    [Benchmark(Description = "Verify Medium Mandate (1KB)")]
    public void VerifyMediumMandate()
    {
        _mediumMandateVerifier!.Verify(_mediumMandateSignature!);
    }

    [Benchmark(Description = "Verify Large Webhook (10KB)")]
    public void VerifyLargeWebhook()
    {
        _largeWebhookVerifier!.Verify(_largeWebhookSignature!);
    }

    [Benchmark(Description = "Verify Extra Large Batch (100KB)")]
    public void VerifyExtraLargeBatch()
    {
        _extraLargeBatchVerifier!.Verify(_extraLargeBatchSignature!);
    }

    [Benchmark(Description = "Verify with Many Headers (20)")]
    public void VerifyManyHeaders()
    {
        _manyHeadersVerifier!.Verify(_manyHeadersSignature!);
    }

    [Benchmark(Description = "Verify Simple GET (no body)")]
    public void VerifySimpleGet()
    {
        _simpleGetVerifier!.Verify(_simpleGetSignature!);
    }

    /// <summary>
    /// Benchmark complete verification workflow including builder creation
    /// </summary>
    [Benchmark(Description = "Full Verify Workflow (Small Payment)")]
    public void FullVerifyWorkflow()
    {
        var scenario = TestData.Scenarios.SmallPayment;
        Verifier.VerifyWithPem(TestData.PublicKeyPem)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body)
            .Verify(_smallPaymentSignature!);
    }

    /// <summary>
    /// Benchmark verification with required headers
    /// </summary>
    [Benchmark(Description = "Verify with Required Headers")]
    public void VerifyWithRequiredHeaders()
    {
        var scenario = TestData.Scenarios.SmallPayment;
        Verifier.VerifyWith(TestData.GetPublicKey())
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body)
            .RequireHeader("Idempotency-Key")
            .RequireHeader("X-Request-Id")
            .Verify(_smallPaymentSignature!);
    }
}

/// <summary>
/// Benchmarks for extracting metadata from signatures
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
public class VerifierMetadataBenchmarks
{
    private string? _signature;
    private string? _signatureWithJku;

    [GlobalSetup]
    public void Setup()
    {
        var scenario = TestData.Scenarios.SmallPayment;

        _signature = Signer.SignWith(TestData.Kid, TestData.GetPrivateKey())
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Body(scenario.Body)
            .Sign();

        _signatureWithJku = Signer.SignWith(TestData.Kid, TestData.GetPrivateKey())
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Body(scenario.Body)
            .Jku("https://webhooks.truelayer.com/.well-known/jwks")
            .Sign();
    }

    [Benchmark(Description = "Extract Kid")]
    public string ExtractKid()
    {
        return Verifier.ExtractKid(_signature!);
    }

    [Benchmark(Description = "Extract Jku")]
    public string ExtractJku()
    {
        return Verifier.ExtractJku(_signatureWithJku!);
    }
}

/// <summary>
/// Benchmarks specifically focused on verifier builder pattern operations
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
public class VerifierBuilderBenchmarks
{
    private System.Security.Cryptography.ECDsa? _publicKey;

    [GlobalSetup]
    public void Setup()
    {
        _publicKey = TestData.GetPublicKey();
    }

    [Benchmark(Description = "Create Verifier Builder")]
    public Verifier CreateBuilder()
    {
        return Verifier.VerifyWith(_publicKey!);
    }

    [Benchmark(Description = "Builder with Method+Path")]
    public Verifier BuilderMethodPath()
    {
        return Verifier.VerifyWith(_publicKey!)
            .Method("POST")
            .Path("/payments");
    }

    [Benchmark(Description = "Builder with Single Header")]
    public Verifier BuilderSingleHeader()
    {
        return Verifier.VerifyWith(_publicKey!)
            .Method("POST")
            .Path("/payments")
            .Header("Idempotency-Key", "idemp-123");
    }

    [Benchmark(Description = "Builder with 5 Headers")]
    public Verifier BuilderFiveHeaders()
    {
        return Verifier.VerifyWith(_publicKey!)
            .Method("POST")
            .Path("/payments")
            .Header("Header-1", "value1")
            .Header("Header-2", "value2")
            .Header("Header-3", "value3")
            .Header("Header-4", "value4")
            .Header("Header-5", "value5");
    }

    [Benchmark(Description = "Builder with Body (1KB)")]
    public Verifier BuilderWithBody()
    {
        return Verifier.VerifyWith(_publicKey!)
            .Method("POST")
            .Path("/payments")
            .Body(TestData.Scenarios.MediumMandate.Body);
    }

    [Benchmark(Description = "Builder with Required Headers")]
    public Verifier BuilderWithRequiredHeaders()
    {
        return Verifier.VerifyWith(_publicKey!)
            .Method("POST")
            .Path("/payments")
            .RequireHeader("Idempotency-Key")
            .RequireHeader("X-Request-Id");
    }
}
