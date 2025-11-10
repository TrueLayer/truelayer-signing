using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using TrueLayer.Signing;

namespace TrueLayer.Signing.Benchmarks;

/// <summary>
/// Benchmarks for JWS detached payload verification optimization.
/// Compares manual JWS reconstruction vs native detached payload support.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class JwsVerificationBenchmarks
{
    private ECDsa? _privateKey;
    private ECDsa? _publicKey;
    private string? _testSignature;

    [GlobalSetup]
    public void Setup()
    {
        _privateKey = TestData.GetPrivateKey();
        _publicKey = TestData.GetPublicKey();

        var scenario = TestData.Scenarios.ManyHeaders;
        _testSignature = Signer.SignWith(TestData.Kid, _privateKey)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body)
            .Sign();
    }

    [Benchmark(Baseline = true, Description = "JWS Verify - OLD (Manual Reconstruction)")]
    public string? JwsVerify_Old_ManualReconstruction()
    {
        var signatureParts = _testSignature!.Split('.');
        var scenario = TestData.Scenarios.ManyHeaders;
        var headers = scenario.Headers.Select(h => (h.Key, Encoding.UTF8.GetBytes(h.Value)));
        var signingPayload = Util.BuildV2SigningPayload(
            scenario.Method,
            scenario.Path,
            headers,
            Encoding.UTF8.GetBytes(scenario.Body)
        );

        var jws = $"{signatureParts[0]}.{Jose.Base64Url.Encode(signingPayload)}.{signatureParts[2]}";

        try
        {
            return Jose.JWT.Decode(jws, _publicKey!);
        }
        catch
        {
            return null;
        }
    }

    [Benchmark(Description = "JWS Verify - NEW (Detached Payload)")]
    public byte[]? JwsVerify_New_DetachedPayload()
    {
        var scenario = TestData.Scenarios.ManyHeaders;
        var headers = scenario.Headers.Select(h => (h.Key, Encoding.UTF8.GetBytes(h.Value)));
        var signingPayload = Util.BuildV2SigningPayload(
            scenario.Method,
            scenario.Path,
            headers,
            Encoding.UTF8.GetBytes(scenario.Body)
        );

        try
        {
            return Jose.JWT.DecodeBytes(_testSignature!, _publicKey!, payload: signingPayload);
        }
        catch
        {
            return null;
        }
    }
}
