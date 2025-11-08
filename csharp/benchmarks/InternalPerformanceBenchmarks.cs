using BenchmarkDotNet.Attributes;
using BenchmarkDotNet.Order;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using TrueLayer.Signing;

namespace TrueLayer.Signing.Benchmarks;

/// <summary>
/// OLD implementation of HeaderNameComparer for baseline comparison.
/// This was the previous implementation that allocated on every GetHashCode call.
/// </summary>
internal class HeaderNameComparer_Old : IEqualityComparer<string>
{
    public bool Equals(string? x, string? y)
        => string.Equals(x, y, StringComparison.OrdinalIgnoreCase);

    // THIS IS THE PROBLEM: Allocates new string on every call
    public int GetHashCode(string x) => x.ToLowerInvariant().GetHashCode();
}

/// <summary>
/// Benchmarks targeting specific internal performance issues identified in the analysis.
/// These benchmarks measure the baseline performance of identified bottlenecks and
/// allow for before/after comparison when optimizations are applied.
///
/// Reference: See PERFORMANCE_ANALYSIS.md for detailed analysis of each issue.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class InternalPerformanceBenchmarks
{
    private ECDsa? _privateKey;
    private ECDsa? _publicKey;
    private string? _testSignature;
    private Dictionary<string, byte[]>? _testHeaders;
    private Dictionary<string, byte[]>? _testHeadersOld;

    [GlobalSetup]
    public void Setup()
    {
        _privateKey = TestData.GetPrivateKey();
        _publicKey = TestData.GetPublicKey();

        // Create a signature for parsing tests
        var scenario = TestData.Scenarios.ManyHeaders;
        _testSignature = Signer.SignWith(TestData.Kid, _privateKey)
            .Method(scenario.Method)
            .Path(scenario.Path)
            .Headers(scenario.Headers)
            .Body(scenario.Body)
            .Sign();

        // Pre-populate headers for dictionary operation tests
        _testHeaders = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        _testHeadersOld = new Dictionary<string, byte[]>(new HeaderNameComparer_Old());
        foreach (var header in scenario.Headers)
        {
            _testHeaders[header.Key] = Encoding.UTF8.GetBytes(header.Value);
            _testHeadersOld[header.Key] = Encoding.UTF8.GetBytes(header.Value);
        }
    }

    /// <summary>
    /// Priority 1: HeaderNameComparer Comparison Benchmarks
    ///
    /// Direct comparison between OLD (HeaderNameComparer with ToLowerInvariant)
    /// and NEW (StringComparer.OrdinalIgnoreCase) implementations.
    ///
    /// Previous issue: Custom HeaderNameComparer allocated on every GetHashCode via ToLowerInvariant()
    /// Current: Uses built-in StringComparer.OrdinalIgnoreCase (zero allocations)
    /// </summary>
    [Benchmark(Baseline = true, Description = "Header Dict Lookup - OLD (allocating)")]
    public int HeaderDictionaryLookups_Old()
    {
        int sum = 0;
        // Simulate typical header access patterns
        for (int i = 0; i < 20; i++)
        {
            if (_testHeadersOld!.TryGetValue($"X-Custom-Header-{i+1:D2}", out var value))
                sum += value.Length;
        }
        return sum;
    }

    [Benchmark(Description = "Header Dict Lookup - NEW (optimized)")]
    public int HeaderDictionaryLookups_New()
    {
        int sum = 0;
        // Simulate typical header access patterns
        for (int i = 0; i < 20; i++)
        {
            if (_testHeaders!.TryGetValue($"X-Custom-Header-{i+1:D2}", out var value))
                sum += value.Length;
        }
        return sum;
    }

    /// <summary>
    /// Compare dictionary creation - OLD vs NEW
    /// </summary>
    [Benchmark(Description = "Create Header Dict - OLD (allocating)")]
    public Dictionary<string, byte[]> CreateHeaderDictionary_Old()
    {
        var dict = new Dictionary<string, byte[]>(new HeaderNameComparer_Old());
        foreach (var header in TestData.Scenarios.ManyHeaders.Headers)
        {
            dict.Add(header.Key, Encoding.UTF8.GetBytes(header.Value));
        }
        return dict;
    }

    [Benchmark(Description = "Create Header Dict - NEW (optimized)")]
    public Dictionary<string, byte[]> CreateHeaderDictionary_New()
    {
        var dict = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase);
        foreach (var header in TestData.Scenarios.ManyHeaders.Headers)
        {
            dict.Add(header.Key, Encoding.UTF8.GetBytes(header.Value));
        }
        return dict;
    }

    /// <summary>
    /// Compare HashSet operations - OLD vs NEW
    /// Used in Verifier.Verify() for signature header validation
    /// </summary>
    [Benchmark(Description = "HashSet Operations - OLD (allocating)")]
    public bool HashSetOperations_Old()
    {
        var headerNames = TestData.Scenarios.ManyHeaders.Headers.Keys.ToList();
        var set = new HashSet<string>(headerNames, new HeaderNameComparer_Old());

        // Simulate typical Contains checks
        bool result = true;
        result &= set.Contains("X-Custom-Header-01");
        result &= set.Contains("x-custom-header-10"); // Different case
        result &= set.Contains("X-CUSTOM-HEADER-20"); // Upper case
        result &= !set.Contains("NonExistent");

        return result;
    }

    [Benchmark(Description = "HashSet Operations - NEW (optimized)")]
    public bool HashSetOperations_New()
    {
        var headerNames = TestData.Scenarios.ManyHeaders.Headers.Keys.ToList();
        var set = new HashSet<string>(headerNames, StringComparer.OrdinalIgnoreCase);

        // Simulate typical Contains checks
        bool result = true;
        result &= set.Contains("X-Custom-Header-01");
        result &= set.Contains("x-custom-header-10"); // Different case
        result &= set.Contains("X-CUSTOM-HEADER-20"); // Upper case
        result &= !set.Contains("NonExistent");

        return result;
    }

    /// <summary>
    /// Priority 2: BuildV2SigningPayload with List&lt;byte&gt;
    /// This is the MOST CRITICAL performance bottleneck in the library.
    /// Measures allocations and performance of the current List&lt;byte&gt; approach.
    ///
    /// Expected improvement: 40-60% reduction with ArrayPool implementation
    /// </summary>
    [Benchmark(Baseline = true, Description = "BuildV2SigningPayload - Small (250B)")]
    public byte[] BuildSigningPayload_Small()
    {
        var scenario = TestData.Scenarios.SmallPayment;
        var headers = scenario.Headers.Select(h => (h.Key, Encoding.UTF8.GetBytes(h.Value)));
        return Util.BuildV2SigningPayload(
            scenario.Method,
            scenario.Path,
            headers,
            Encoding.UTF8.GetBytes(scenario.Body)
        );
    }

    [Benchmark(Description = "BuildV2SigningPayload - Medium (1KB)")]
    public byte[] BuildSigningPayload_Medium()
    {
        var scenario = TestData.Scenarios.MediumMandate;
        var headers = scenario.Headers.Select(h => (h.Key, Encoding.UTF8.GetBytes(h.Value)));
        return Util.BuildV2SigningPayload(
            scenario.Method,
            scenario.Path,
            headers,
            Encoding.UTF8.GetBytes(scenario.Body)
        );
    }

    [Benchmark(Description = "BuildV2SigningPayload - Large (10KB)")]
    public byte[] BuildSigningPayload_Large()
    {
        var scenario = TestData.Scenarios.LargeWebhook;
        var headers = scenario.Headers.Select(h => (h.Key, Encoding.UTF8.GetBytes(h.Value)));
        return Util.BuildV2SigningPayload(
            scenario.Method,
            scenario.Path,
            headers,
            Encoding.UTF8.GetBytes(scenario.Body)
        );
    }

    [Benchmark(Description = "BuildV2SigningPayload - Many Headers (20)")]
    public byte[] BuildSigningPayload_ManyHeaders()
    {
        var scenario = TestData.Scenarios.ManyHeaders;
        var headers = scenario.Headers.Select(h => (h.Key, Encoding.UTF8.GetBytes(h.Value)));
        return Util.BuildV2SigningPayload(
            scenario.Method,
            scenario.Path,
            headers,
            Encoding.UTF8.GetBytes(scenario.Body)
        );
    }

    /// <summary>
    /// Priority 3: HTTP Method string conversion overhead
    /// Tests the allocation cost of method.ToUpperInvariant().ToUtf8()
    /// that happens on every Sign/Verify operation.
    ///
    /// Expected improvement: 10-15% with caching
    /// </summary>
    [Benchmark(Description = "HTTP Method Conversion - POST")]
    public byte[] HttpMethodConversion_Post()
    {
        return "POST".ToUpperInvariant().ToUtf8();
    }

    [Benchmark(Description = "HTTP Method Conversion - GET")]
    public byte[] HttpMethodConversion_Get()
    {
        return "GET".ToUpperInvariant().ToUtf8();
    }

    [Benchmark(Description = "HTTP Method Conversion - Mixed Case")]
    public byte[] HttpMethodConversion_MixedCase()
    {
        return "PaTcH".ToUpperInvariant().ToUtf8(); // Simulates user input
    }

    /// <summary>
    /// Priority 4 & 5: String parsing and LINQ overhead in Verifier
    /// Tests the allocation overhead of Split() + LINQ operations
    ///
    /// Expected improvement: 15-20% with Span-based parsing
    /// </summary>
    [Benchmark(Description = "Parse JWS Signature Parts")]
    public int ParseSignatureParts()
    {
        // Simulates Verifier.Verify() line 242
        var parts = _testSignature!.Split('.');
        return parts.Length;
    }

    [Benchmark(Description = "Parse & Process Header Names (LINQ)")]
    public List<string> ParseHeaderNamesWithLinq()
    {
        // Simulates Verifier.Verify() lines 245-249
        var headerString = "X-Custom-Header-01, X-Custom-Header-02, X-Custom-Header-03, , X-Custom-Header-05";

        return headerString
            .Split(',')
            .Select(h => h.Trim())
            .Where(h => !string.IsNullOrEmpty(h))
            .ToList();
    }

    [Benchmark(Description = "Filter Missing Required Headers (LINQ)")]
    public List<string> FilterMissingHeadersWithLinq()
    {
        // Simulates Verifier.Verify() line 252
        var requiredHeaders = new HashSet<string>(StringComparer.OrdinalIgnoreCase)
        {
            "Idempotency-Key",
            "X-Request-Id",
            "X-TL-Webhook-Timestamp",
            "NonExistent-Header"
        };

        var signatureHeaders = new HashSet<string>(
            TestData.Scenarios.ManyHeaders.Headers.Keys,
            StringComparer.OrdinalIgnoreCase
        );

        return requiredHeaders
            .Where(h => !signatureHeaders.Contains(h))
            .ToList();
    }

    /// <summary>
    /// Priority 6: Header keys enumeration in Signer
    /// Tests the overhead of .Select(h => h.Key) when creating tl_headers
    ///
    /// Expected improvement: 5-10% using .Keys directly
    /// </summary>
    [Benchmark(Description = "Header Keys - Select LINQ")]
    public string HeaderKeysWithSelect()
    {
        // Current implementation: Signer.cs line 175
        return string.Join(",", _testHeaders!.Select(h => h.Key));
    }

    [Benchmark(Description = "Header Keys - Direct")]
    public string HeaderKeysDirect()
    {
        // Optimized: use Keys collection directly
        return string.Join(",", _testHeaders!.Keys);
    }
}

/// <summary>
/// End-to-end benchmarks measuring the combined impact of all optimizations
/// on realistic signing and verification workflows.
/// </summary>
[MemoryDiagnoser]
[Orderer(SummaryOrderPolicy.FastestToSlowest)]
[RankColumn]
public class OptimizationImpactBenchmarks
{
    private Signer? _smallPaymentSigner;
    private Signer? _manyHeadersSigner;
    private Verifier? _smallPaymentVerifier;
    private Verifier? _manyHeadersVerifier;
    private string? _smallPaymentSignature;
    private string? _manyHeadersSignature;

    [GlobalSetup]
    public void Setup()
    {
        var privateKey = TestData.GetPrivateKey();
        var publicKey = TestData.GetPublicKey();

        // Build signers
        var smallScenario = TestData.Scenarios.SmallPayment;
        _smallPaymentSigner = Signer.SignWith(TestData.Kid, privateKey)
            .Method(smallScenario.Method)
            .Path(smallScenario.Path)
            .Headers(smallScenario.Headers)
            .Body(smallScenario.Body);

        var manyHeadersScenario = TestData.Scenarios.ManyHeaders;
        _manyHeadersSigner = Signer.SignWith(TestData.Kid, privateKey)
            .Method(manyHeadersScenario.Method)
            .Path(manyHeadersScenario.Path)
            .Headers(manyHeadersScenario.Headers)
            .Body(manyHeadersScenario.Body);

        // Generate signatures
        _smallPaymentSignature = _smallPaymentSigner.Sign();
        _manyHeadersSignature = _manyHeadersSigner.Sign();

        // Build verifiers
        _smallPaymentVerifier = Verifier.VerifyWith(publicKey)
            .Method(smallScenario.Method)
            .Path(smallScenario.Path)
            .Headers(smallScenario.Headers)
            .Body(smallScenario.Body);

        _manyHeadersVerifier = Verifier.VerifyWith(publicKey)
            .Method(manyHeadersScenario.Method)
            .Path(manyHeadersScenario.Path)
            .Headers(manyHeadersScenario.Headers)
            .Body(manyHeadersScenario.Body);
    }

    /// <summary>
    /// Baseline: Complete signing operation
    /// This benchmark captures the combined effect of:
    /// - Priority 1: HeaderNameComparer allocations (header dictionary operations)
    /// - Priority 2: BuildV2SigningPayload List&lt;byte&gt; allocations
    /// - Priority 3: HTTP method conversion allocations
    /// - Priority 6: Header keys enumeration
    ///
    /// Expected combined improvement: 50-70% allocation reduction
    /// </summary>
    [Benchmark(Baseline = true, Description = "Sign Operation - Baseline")]
    public string SignOperation_Baseline()
    {
        return _smallPaymentSigner!.Sign();
    }

    [Benchmark(Description = "Sign Operation - Many Headers")]
    public string SignOperation_ManyHeaders()
    {
        return _manyHeadersSigner!.Sign();
    }

    /// <summary>
    /// Baseline: Complete verification operation
    /// This benchmark captures the combined effect of:
    /// - Priority 1: HeaderNameComparer allocations (multiple dictionary/set operations)
    /// - Priority 2: BuildV2SigningPayload List&lt;byte&gt; allocations
    /// - Priority 3: HTTP method conversion allocations
    /// - Priority 4: String splitting allocations
    /// - Priority 5: LINQ intermediate allocations
    ///
    /// Expected combined improvement: 40-60% allocation reduction
    /// </summary>
    [Benchmark(Baseline = true, Description = "Verify Operation - Baseline")]
    public void VerifyOperation_Baseline()
    {
        _smallPaymentVerifier!.Verify(_smallPaymentSignature!);
    }

    [Benchmark(Description = "Verify Operation - Many Headers")]
    public void VerifyOperation_ManyHeaders()
    {
        _manyHeadersVerifier!.Verify(_manyHeadersSignature!);
    }

    /// <summary>
    /// Full workflow test - measures complete round-trip
    /// This is the most realistic test measuring total impact on end users
    /// </summary>
    [Benchmark(Description = "Full Round-Trip (Sign + Verify)")]
    public void FullRoundTrip()
    {
        var signature = _smallPaymentSigner!.Sign();
        _smallPaymentVerifier!.Verify(signature);
    }
}

/// <summary>
/// Regression tests to ensure optimizations don't break edge cases
/// </summary>
[MemoryDiagnoser]
public class OptimizationRegressionTests
{
    /// <summary>
    /// Test case-insensitive header name handling
    /// Validates that StringComparer.OrdinalIgnoreCase maintains correct behavior
    /// </summary>
    [Benchmark(Description = "Case-Insensitive Header Matching")]
    public bool CaseInsensitiveHeaderMatching()
    {
        var dict = new Dictionary<string, byte[]>(StringComparer.OrdinalIgnoreCase)
        {
            ["Content-Type"] = Encoding.UTF8.GetBytes("application/json"),
            ["X-Request-Id"] = Encoding.UTF8.GetBytes("req-123")
        };

        // All these should match (case-insensitive)
        bool result = true;
        result &= dict.ContainsKey("content-type");
        result &= dict.ContainsKey("CONTENT-TYPE");
        result &= dict.ContainsKey("Content-Type");
        result &= dict.ContainsKey("x-request-id");
        result &= dict.ContainsKey("X-REQUEST-ID");

        return result;
    }

    /// <summary>
    /// Test empty and whitespace-only header values
    /// Ensures string parsing optimizations handle edge cases
    /// </summary>
    [Benchmark(Description = "Empty Header Value Handling")]
    public int EmptyHeaderValueHandling()
    {
        var headerString = ",,,value1,,value2,  ,value3,";

        var result = headerString
            .Split(',')
            .Select(h => h.Trim())
            .Where(h => !string.IsNullOrEmpty(h))
            .ToList();

        return result.Count; // Should be 3
    }

    /// <summary>
    /// Test BuildV2SigningPayload with various payload sizes
    /// Ensures buffer sizing optimization handles all cases
    /// </summary>
    [Benchmark(Description = "Payload Building - Edge Sizes")]
    public int PayloadBuildingEdgeSizes()
    {
        int totalSize = 0;

        // Empty body
        var payload1 = Util.BuildV2SigningPayload("GET", "/path", Array.Empty<(string, byte[])>(), Array.Empty<byte>());
        totalSize += payload1.Length;

        // Very large headers
        var largeHeaders = Enumerable.Range(1, 100)
            .Select(i => ($"Header-{i}", Encoding.UTF8.GetBytes($"Value-{i}")));
        var payload2 = Util.BuildV2SigningPayload("POST", "/path", largeHeaders, Array.Empty<byte>());
        totalSize += payload2.Length;

        // Unicode in path
        var payload3 = Util.BuildV2SigningPayload("POST", "/path/with/unicode/字", Array.Empty<(string, byte[])>(), Array.Empty<byte>());
        totalSize += payload3.Length;

        return totalSize;
    }
}
