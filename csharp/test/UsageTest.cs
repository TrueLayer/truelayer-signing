using Xunit;
using TrueLayer.Signing;
using System;
using FluentAssertions;
using System.IO;

namespace Tests
{
    public class UsageTest
    {
        internal const string Kid = "45fc75cf-5649-4134-84b3-192c2c78e990";
        internal static string PrivateKey = File.ReadAllText(TestResourcePath("ec512-private.pem"));
        internal static string PublicKey = File.ReadAllText(TestResourcePath("ec512-public.pem"));

        [Fact]
        public void SignAndVerify()
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

            Verifier.VerifyWithPem(PublicKey)
                .Method("post") // case-insensitive: no troubles
                .Path(path)
                .Header("X-Whatever-2", "t2345d")
                .Header("Idempotency-Key", idempotency_key)
                .Body(body)
                .Verify(tlSignature); // should not throw
        }

        [Fact]
        public void SignAndVerify_NoHeaders()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Body(body)
                .Sign();

            Verifier.VerifyWithPem(PublicKey)
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

        /// <summary>Return working path to /test-resources/$subpath</summary>
        private static string TestResourcePath(string subpath)
            => Path.Combine("../../../../../test-resources", subpath);
    }
}
