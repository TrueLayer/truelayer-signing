using System.Text.Json;
using System.Text.Json.Serialization;
using BenchmarkDotNet.Attributes;
using TrueLayer.Signing;

namespace Benchmarks;

[MemoryDiagnoser]
public class SignerBenchmarks
{
    private const string PrivateKey = @"-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIALJ2sKM+8mVDfTIlk50rqB5lkxaLBt+OECvhXq3nEaB+V0nqljZ9c
5aHRN3qqxMzNLvxFQ+4twifa4ezkMK2/j5WgBwYFK4EEACOhgYkDgYYABADmhZbj
i8bgJRfMTdtzy+5VbS5ScMaKC1LQfhII+PTzGzOr+Ts7Qv8My5cmYU5qarGK3tWF
c3VMlcFZw7Y0iLjxAQFPvHqJ9vn3xWp+d3JREU1vQJ9daXswwbcoer88o1oVFmFf
WS1/11+TH1x/lgKckAws6sAzJLPtCUZLV4IZTb6ENg==
-----END EC PRIVATE KEY-----";

    private static readonly string Json = JsonSerializer.Serialize(new TestObject(), SerializerOptions.Default);

    [Benchmark]
    public string SignWithPem()
        => Signer.SignWithPem(Guid.NewGuid().ToString(), PrivateKey)
            .Method("POST")
            .Path("/payments")
            .Body(Json)
            .Header("Idempotency-Key", "idempotency-key")
            .Sign();

    [Benchmark]
    public string SignWithPem_Static()
        => Signer.Sign(
            new Dictionary<string, string>{{"Idempotency-Key", "idempotency-key"}},
            Guid.NewGuid().ToString(),
            PrivateKey,
            HttpMethod.Post,
            "/payments",
            Json);

    [Benchmark]
    public string SignWithPem_Static_Sb()
        => Signer.SignSb(
            new Dictionary<string, string>{{"Idempotency-Key", "idempotency-key"}},
            Guid.NewGuid().ToString(),
            PrivateKey,
            HttpMethod.Post,
            "/payments",
            Json);
}

public class TestObject
{
    public string PropA { get; }
    public string PropB { get; }
    public string PropC { get; }

    public TestObject()
    {
        PropA = "prop-a";
        PropB = "prop-b";
        PropC = "prop-c";
    }
}

internal static class SerializerOptions
{
    public static readonly JsonSerializerOptions Default = new()
    {
        DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull,
    };
}
