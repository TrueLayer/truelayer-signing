using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;

namespace TrueLayer.Signing.Benchmarks;

/// <summary>
/// Realistic test data for benchmarking based on actual TrueLayer API usage patterns
/// </summary>
public static class TestData
{
    // Realistic EC P-521 key pair for ES512 (from test-resources)
    public const string PrivateKeyPem = @"-----BEGIN EC PRIVATE KEY-----
MIHcAgEBBEIBMJmRfU/nMzOnBnA6zXgdfpF6uWfYvOBCM4lUoxFDSFS6nqO3+X+R
42GJ8OzKzLr9+Iq238CL+2Bxw14f3jqiTtCgBwYFK4EEACOhgYkDgYYABACgu5bi
cWqhS5Hx3sVWxSgjraWJth1CVYa0tK2ep250tj3ZtDStrl5kBuS6esZNH37D2avi
jYS3JvqkLtgHb7bdYwF9XI5BjIpbYpD65F+PasLiQ3XBE2k7I/pMhT/I7BfVuVwA
d2eLQYkLXO9g0JyWHisgFf0+qmU7RSha/k6eIrvo+w==
-----END EC PRIVATE KEY-----";

    public const string PublicKeyPem = @"-----BEGIN PUBLIC KEY-----
MIGbMBAGByqGSM49AgEGBSuBBAAjA4GGAAQAoLuW4nFqoUuR8d7FVsUoI62libYd
QlWGtLStnqdudLY92bQ0ra5eZAbkunrGTR9+w9mr4o2Etyb6pC7YB2+23WMBfVyO
QYyKW2KQ+uRfj2rC4kN1wRNpOyP6TIU/yOwX1blcAHdni0GJC1zvYNCclh4rIBX9
PqplO0UoWv5OniK76Ps=
-----END PUBLIC KEY-----";

    public const string Kid = "45fc75cf-5649-4134-84b3-192c2c78e990";

    // Realistic API request scenarios
    public static class Scenarios
    {
        // Small payment request (typical)
        public static readonly RequestScenario SmallPayment = new(
            Name: "Small Payment (250 bytes)",
            Method: "POST",
            Path: "/payments",
            Headers: new Dictionary<string, string>
            {
                ["Idempotency-Key"] = "idemp-2076717c-9005-4811-a321-9e0787fa0382",
                ["X-Request-Id"] = "req-550e8400-e29b-41d4-a716-446655440000"
            },
            Body: @"{""amount_in_minor"":5000,""currency"":""GBP"",""payment_method"":{""type"":""bank_transfer"",""provider_selection"":{""type"":""user_selected""}},""user"":{""id"":""user-123""}}"
        );

        // Medium mandate request
        public static readonly RequestScenario MediumMandate = new(
            Name: "Medium Mandate (1KB)",
            Method: "POST",
            Path: "/merchant-accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/mandates",
            Headers: new Dictionary<string, string>
            {
                ["Idempotency-Key"] = "idemp-mandate-12345",
                ["X-Request-Id"] = "req-mandate-67890",
                ["X-TL-Webhook-Timestamp"] = "2021-11-29T11:42:55Z"
            },
            Body: GenerateJsonBody(1024)
        );

        // Large webhook payload
        public static readonly RequestScenario LargeWebhook = new(
            Name: "Large Webhook (10KB)",
            Method: "POST",
            Path: "/tl-webhook",
            Headers: new Dictionary<string, string>
            {
                ["X-TL-Webhook-Timestamp"] = "2021-11-29T11:42:55Z",
                ["Content-Type"] = "application/json",
                ["X-TL-Signature"] = "placeholder"
            },
            Body: GenerateJsonBody(10240)
        );

        // Extra large batch payload
        public static readonly RequestScenario ExtraLargeBatch = new(
            Name: "Extra Large Batch (100KB)",
            Method: "POST",
            Path: "/payments/batch",
            Headers: new Dictionary<string, string>
            {
                ["Idempotency-Key"] = "idemp-batch-" + Guid.NewGuid(),
                ["X-Request-Id"] = "req-batch-" + Guid.NewGuid(),
                ["Content-Type"] = "application/json"
            },
            Body: GenerateJsonBody(102400)
        );

        // Many headers scenario
        public static readonly RequestScenario ManyHeaders = new(
            Name: "Many Headers (20 headers)",
            Method: "POST",
            Path: "/payments",
            Headers: Enumerable.Range(1, 20)
                .ToDictionary(
                    i => $"X-Custom-Header-{i:D2}",
                    i => $"value-{i}"
                ),
            Body: SmallPayment.Body
        );

        // Simple GET request (no body)
        public static readonly RequestScenario SimpleGet = new(
            Name: "Simple GET (no body)",
            Method: "GET",
            Path: "/payments/123e4567-e89b-12d3-a456-426614174000",
            Headers: new Dictionary<string, string>
            {
                ["X-Request-Id"] = "req-get-123"
            },
            Body: ""
        );

        private static string GenerateJsonBody(int targetSize)
        {
            var items = new List<string>();
            // Double braces {{ }} are escaped in format strings
            var baseItem = @"{{""id"":""item-{0}"",""amount"":1000,""currency"":""GBP"",""description"":""Payment {0}"",""metadata"":{{""key1"":""value1"",""key2"":""value2""}}}}";

            var currentSize = 20; // Account for array brackets
            var itemIndex = 0;

            while (currentSize < targetSize)
            {
                var item = string.Format(baseItem, itemIndex++);
                items.Add(item);
                currentSize += item.Length + 1; // +1 for comma
            }

            return $"[{string.Join(",", items)}]";
        }
    }

    public record RequestScenario(
        string Name,
        string Method,
        string Path,
        Dictionary<string, string> Headers,
        string Body
    );

    // Pre-generated keys for benchmarking (avoid key generation overhead)
    private static readonly Lazy<ECDsa> _privateKey = new(() =>
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(PrivateKeyPem);
        return ecdsa;
    });

    private static readonly Lazy<ECDsa> _publicKey = new(() =>
    {
        var ecdsa = ECDsa.Create();
        ecdsa.ImportFromPem(PublicKeyPem);
        return ecdsa;
    });

    public static ECDsa GetPrivateKey() => _privateKey.Value;
    public static ECDsa GetPublicKey() => _publicKey.Value;
}
