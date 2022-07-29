using Xunit;
using System;
using System.Collections.Generic;
using FluentAssertions;
using System.IO;
using System.Linq;
using System.Net.Http;
using static TrueLayer.Signing.Tests.TestData;

namespace TrueLayer.Signing.Tests
{
    public class UsageTest
    {
        public static IEnumerable<object[]> TestCases = new[]
        {
            new TestCase(
                "Shared Test Key",
                Kid,
                PrivateKey,
                PublicKey),
            new TestCase(
                "Length Error Reproduction",
                BugReproduction.LengthError.Kid,
                BugReproduction.LengthError.PrivateKey,
                BugReproduction.LengthError.PublicKey),
        }.Select(x => new object[] {x});

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify(TestCase testCase)
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(testCase.Kid, testCase.PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Sign();

            Verifier.VerifyWithPem(testCase.PublicKey)
                .Method("post") // case-insensitive: no troubles
                .Path(path)
                .Header("X-Whatever-2", "t2345d")
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Verify(tlSignature); // should not throw
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_Static(TestCase testCase)
        {
            const string body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            const string idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            const string path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var headers = new Dictionary<string, string>
            {
                { "Idempotency-Key", idempotencyKey },
            };
            var tlSignature = Signer.Sign(
                headers,
                testCase.Kid,
                testCase.PrivateKey,
                HttpMethod.Post,
                path,
                body);

            Verifier.VerifyWithPem(testCase.PublicKey)
                .Method("post") // case-insensitive: no troubles
                .Path(path)
                .Header("X-Whatever-2", "t2345d")
                .Header("Idempotency-Key", idempotencyKey)
                .Body(body)
                .Verify(tlSignature); // should not throw
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_Static_Sb(TestCase testCase)
        {
            const string body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            const string idempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            const string path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var headers = new Dictionary<string, string>
            {
                { "Idempotency-Key", idempotencyKey },
            };
            var tlSignature = Signer.SignSb(
                headers,
                testCase.Kid,
                testCase.PrivateKey,
                HttpMethod.Post,
                path,
                body);

            Verifier.VerifyWithPem(testCase.PublicKey)
                .Method("post") // case-insensitive: no troubles
                .Path(path)
                .Header("X-Whatever-2", "t2345d")
                .Header("Idempotency-Key", idempotencyKey)
                .Body(body)
                .Verify(tlSignature); // should not throw
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_NoHeaders(TestCase testCase)
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(testCase.Kid, testCase.PrivateKey)
                .Method("POST")
                .Path(path)
                .Body(body)
                .Sign();

            Verifier.VerifyWithPem(testCase.PublicKey)
                .Method("POST")
                .Path(path)
                .Body(body)
                .Verify(tlSignature); // should not throw
        }

        // Verify the a static signature used in all lang tests to ensure
        // cross-lang consistency and prevent regression.
        [Fact]
        public void VerifyStaticSignature()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";
            var tlSignature = File.ReadAllText(TestResourcePath("tl-signature.txt")).Trim();

            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path(path)
                .Header("X-Whatever-2", "t2345d")
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Verify(tlSignature); // should not throw
        }

        [Fact]
        public void SignAndVerify_MethodMismatch()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("DELETE") // different
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void SignAndVerify_PathMismatch()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/merchant_accounts/67b5b1cf-1d0c-45d4-a2ea-61bdc044327c/sweeping") // different
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void SignAndVerify_HeaderMismatch()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", "something-else") // different
                .Body(body)
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void SignAndVerify_BodyMismatch()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Body("{\"currency\":\"GBP\",\"max_amount_in_minor\":5000001}") // different
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void SignAndVerify_MissingSignatureHeader()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path(path)
                // missing Idempotency-Key
                .Body(body)
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void SignAndVerify_RequiredHeaderMissingFromSignature()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path(path)
                .RequireHeader("X-Required") // missing from signature
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void SignAndVerify_FlexibleHeaderCaseOrderVerify()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Header("X-Custom", "123")
                .Body(body)
                .Sign();

            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path(path)
                .Header("X-CUSTOM", "123") // different order & case, it's ok!
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Verify(tlSignature);
        }

        [Fact]
        public void Verifier_ExtractKid()
        {
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("delete")
                .Path("/foo")
                .Header("X-Custom", "123")
                .Sign();

            Verifier.ExtractKid(tlSignature).Should().Be(Kid);
        }

        [Fact]
        public void Verifier_ExtractJku()
        {
            var tlSignature = File.ReadAllText(TestResourcePath("webhook-signature.txt")).Trim();
            Verifier.ExtractJku(tlSignature).Should().Be("https://webhooks.truelayer.com/.well-known/jwks");
        }

        [Fact]
        public void Verifier_Jwks()
        {
            var tlSignature = File.ReadAllText(TestResourcePath("webhook-signature.txt")).Trim();
            var jwks = File.ReadAllText(TestResourcePath("jwks.json"));

            Verifier.VerifyWithJwks(jwks)
                .Method("POST")
                .Path("/tl-webhook")
                .Header("x-tl-webhook-timestamp", "2021-11-29T11:42:55Z")
                .Header("content-type", "application/json")
                .Body("{\"event_type\":\"example\",\"event_id\":\"18b2842b-a57b-4887-a0a6-d3c7c36f1020\"}")
                .Verify(tlSignature); // should not throw

            Action verify = () => Verifier.VerifyWithJwks(jwks)
                .Method("POST")
                .Path("/tl-webhook")
                .Header("x-tl-webhook-timestamp", "2021-12-02T14:18:00Z") // different
                .Header("content-type", "application/json")
                .Body("{\"event_type\":\"example\",\"event_id\":\"18b2842b-a57b-4887-a0a6-d3c7c36f1020\"}")
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        public sealed class TestCase
        {
            public TestCase(string name, string kid, string privateKey, string publicKey)
            {
                Name = name;
                Kid = kid;
                PrivateKey = privateKey;
                PublicKey = publicKey;
            }

            private string Name { get; }
            public string Kid { get; }
            public string PrivateKey { get; }
            public string PublicKey { get; }

            public override string ToString() => Name;
        }
    }
}
