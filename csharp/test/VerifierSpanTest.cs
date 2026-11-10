#if NET8_0_OR_GREATER
using Xunit;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using AwesomeAssertions;
using static TrueLayer.Signing.Tests.TestData;

namespace TrueLayer.Signing.Tests
{
    /// <summary>
    /// Tests for the high-performance span-based VerifierSpan API.
    /// These tests mirror the key scenarios from UsageTest.cs to ensure feature parity.
    /// </summary>
    public class VerifierSpanTest
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
        }.Select(x => new object[] { x });

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_WithPem(TestCase testCase)
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

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("X-Whatever-2", Encoding.UTF8.GetBytes("t2345d")),
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotency_key))
            };

            // Verify with PEM parsing
            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(testCase.PublicKey),
                "post", // case-insensitive: no troubles
                path,
                headers,
                Encoding.UTF8.GetBytes(body),
                tlSignature
            ); // should not throw
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_PreParsedKey(TestCase testCase)
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

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("X-Whatever-2", Encoding.UTF8.GetBytes("t2345d")),
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotency_key))
            };

            using var publicKey = testCase.PublicKey.AsSpan().ParsePem();

            // Verify with pre-parsed key (most optimized path)
            VerifierSpan.VerifyWith(
                publicKey,
                "post", // case-insensitive: no troubles
                path,
                headers,
                Encoding.UTF8.GetBytes(body),
                tlSignature
            ); // should not throw
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

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(testCase.PublicKey),
                "POST",
                path,
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes(body),
                tlSignature
            ); // should not throw
        }

        [Theory]
        [InlineData("/tl-webhook/", "/tl-webhook")]
        [InlineData("/tl-webhook", "/tl-webhook/")]
        public void SignAndVerify_TrailingSlash(string signedPath, string verifyPath)
        {
            var body = "{\"foo\":\"bar\"}";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(signedPath)
                .Body(body)
                .Sign();

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                verifyPath,
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes(body),
                tlSignature
            );
        }

        [Fact]
        public void VerifyStaticSignature()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000,\"name\":\"Foo???\"}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";
            var tlSignature = System.IO.File.ReadAllText(TestResourcePath("tl-signature.txt")).Trim();

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("X-Whatever-2", Encoding.UTF8.GetBytes("t2345d")),
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotency_key))
            };

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                headers,
                Encoding.UTF8.GetBytes(body),
                tlSignature
            ); // should not throw
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

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotency_key))
            };

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "DELETE", // different
                path,
                headers,
                Encoding.UTF8.GetBytes(body),
                tlSignature
            );

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

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotency_key))
            };

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                "/merchant_accounts/67b5b1cf-1d0c-45d4-a2ea-61bdc044327c/sweeping", // different
                headers,
                Encoding.UTF8.GetBytes(body),
                tlSignature
            );

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

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes("something-else")) // different
            };

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                headers,
                Encoding.UTF8.GetBytes(body),
                tlSignature
            );

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

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotency_key))
            };

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                headers,
                Encoding.UTF8.GetBytes("{\"currency\":\"GBP\",\"max_amount_in_minor\":5000001}"), // different
                tlSignature
            );

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

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                Array.Empty<KeyValuePair<string, byte[]>>(), // missing Idempotency-Key
                Encoding.UTF8.GetBytes(body),
                tlSignature
            );

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

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotency_key))
            };

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                headers,
                Encoding.UTF8.GetBytes(body),
                tlSignature,
                requiredHeaders: new[] { "X-Required" } // missing from signature
            );

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void SignAndVerify_RequiredHeaderCaseInsensitivity()
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

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("iDeMpOtEnCy-kEy", Encoding.UTF8.GetBytes(idempotency_key))
            };

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                headers,
                Encoding.UTF8.GetBytes(body),
                tlSignature,
                requiredHeaders: new[] { "IdEmPoTeNcY-KeY" }
            ); // should not throw
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

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("X-CUSTOM", Encoding.UTF8.GetBytes("123")), // different order & case
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotency_key))
            };

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                headers,
                Encoding.UTF8.GetBytes(body),
                tlSignature
            );
        }

        [Fact]
        public void SignAndVerify_HeaderNameWhitespaceTrimming()
        {
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var idempotency_key = "idemp-2076717c-9005-4811-a321-9e0787fa0382";
            var path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";

            // Sign with header names that have leading/trailing whitespace
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("  Idempotency-Key  ", idempotency_key)
                .Header("\tX-Custom\t", "123")
                .Body(body)
                .Sign();

            // Verify with trimmed header names - should work
            var headers1 = new[]
            {
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotency_key)),
                new KeyValuePair<string, byte[]>("X-Custom", Encoding.UTF8.GetBytes("123"))
            };

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                headers1,
                Encoding.UTF8.GetBytes(body),
                tlSignature
            );

            // Verify the reverse: sign without whitespace, verify with whitespace
            var tlSignature2 = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Header("Idempotency-Key", idempotency_key)
                .Header("X-Custom", "123")
                .Body(body)
                .Sign();

            var headers2 = new[]
            {
                new KeyValuePair<string, byte[]>("  Idempotency-Key  ", Encoding.UTF8.GetBytes(idempotency_key)),
                new KeyValuePair<string, byte[]>("\tX-Custom\t", Encoding.UTF8.GetBytes("123"))
            };

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                headers2,
                Encoding.UTF8.GetBytes(body),
                tlSignature2
            );
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_EmptyBody_NotProvided(TestCase testCase)
        {
            // Test with empty body span
            var path = "/test/empty-body";

            var tlSignature = Signer.SignWithPem(testCase.Kid, testCase.PrivateKey)
                .Method("POST")
                .Path(path)
                .Sign();

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(testCase.PublicKey),
                "POST",
                path,
                Array.Empty<KeyValuePair<string, byte[]>>(),
                ReadOnlySpan<byte>.Empty,
                tlSignature
            ); // should not throw
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_EmptyBody_EmptyArray(TestCase testCase)
        {
            // Test with empty byte array
            var path = "/test/empty-array";

            var tlSignature = Signer.SignWithPem(testCase.Kid, testCase.PrivateKey)
                .Method("POST")
                .Path(path)
                .Body(Array.Empty<byte>())
                .Sign();

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(testCase.PublicKey),
                "POST",
                path,
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Array.Empty<byte>(),
                tlSignature
            ); // should not throw
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_EmptyBody_InterchangeableForms(TestCase testCase)
        {
            // All forms of empty body should be interchangeable
            var path = "/test/empty-interchange";

            // Sign with not called (empty)
            var sig1 = Signer.SignWithPem(testCase.Kid, testCase.PrivateKey)
                .Method("POST")
                .Path(path)
                .Sign();

            // Verify with empty span - should work
            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(testCase.PublicKey),
                "POST",
                path,
                Array.Empty<KeyValuePair<string, byte[]>>(),
                ReadOnlySpan<byte>.Empty,
                sig1
            );

            // Sign with empty string
            var sig2 = Signer.SignWithPem(testCase.Kid, testCase.PrivateKey)
                .Method("POST")
                .Path(path)
                .Body("")
                .Sign();

            // Verify with empty array - should work
            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(testCase.PublicKey),
                "POST",
                path,
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Array.Empty<byte>(),
                sig2
            );
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_EmptyBody_Mismatch(TestCase testCase)
        {
            // Empty body vs non-empty body should fail verification
            var path = "/test/empty-mismatch";

            var tlSignature = Signer.SignWithPem(testCase.Kid, testCase.PrivateKey)
                .Method("POST")
                .Path(path)
                .Body("") // empty
                .Sign();

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(testCase.PublicKey),
                "POST",
                path,
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes("{}"), // not empty
                tlSignature
            );

            verify.Should().Throw<SignatureException>();
        }

        [Theory]
        [MemberData(nameof(TestCases))]
        public void SignAndVerify_EmptyBody_WithHeaders(TestCase testCase)
        {
            // Empty body with headers should work
            var path = "/test/empty-with-headers";
            var idempotencyKey = "idemp-empty-body-test";

            var tlSignature = Signer.SignWithPem(testCase.Kid, testCase.PrivateKey)
                .Method("DELETE")
                .Path(path)
                .Header("Idempotency-Key", idempotencyKey)
                .Body(Array.Empty<byte>())
                .Sign();

            var headers = new[]
            {
                new KeyValuePair<string, byte[]>("Idempotency-Key", Encoding.UTF8.GetBytes(idempotencyKey))
            };

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(testCase.PublicKey),
                "DELETE",
                path,
                headers,
                ReadOnlySpan<byte>.Empty,
                tlSignature
            ); // should not throw
        }

        [Fact]
        public void InvalidPath_ShouldThrowArgumentException()
        {
            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                "https://example.com/the-path", // invalid - doesn't start with '/'
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Array.Empty<byte>(),
                "dummy..signature"
            );

            verify.Should().Throw<ArgumentException>()
                .WithMessage("Invalid path \"https://example.com/the-path\" must start with '/'");
        }

        [Theory]
        [InlineData("nodots")]
        [InlineData("one.dot")]
        [InlineData("too.many.dots.here")]
        public void InvalidSignatureFormat_ShouldThrowSignatureException(string invalidSignature)
        {
            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                "/test",
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes("{}"),
                invalidSignature
            );

            verify.Should().Throw<SignatureException>()
                .WithMessage("invalid signature format, expected detached JWS (header..signature)");
        }

        [Fact]
        public void BadKey_ShouldThrowArgumentException()
        {
            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes("not-a-key"),
                "POST",
                "/foo",
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes("{}"),
                "dummy..signature"
            );

            verify.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void BadSignature_ShouldThrowSignatureException()
        {
            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                "/foo",
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes("{}"),
                "not-a-signature"
            );

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void InvalidButPreAttachedJwsBody_ShouldThrowSignatureException()
        {
            // Signature for `/bar` but we're verifying against `/foo` - should fail
            const string signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
                + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV"
                + "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
                + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
                + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
                + "d2d3D17Wd9UA";

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                "/foo", // not /bar so should fail
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes("{}"),
                signature
            );

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void InvalidButPreAttachedJwsBodyTrailingDots_ShouldThrowSignatureException()
        {
            // Signature for `/bar` but with trailing dots - should fail
            const string signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
                + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV"
                + "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
                + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
                + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
                + "d2d3D17Wd9UA....";

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                "/foo", // not /bar so should fail
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes("{}"),
                signature
            );

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void TamperedSignature_ShouldThrowSignatureException()
        {
            // Create a valid signature, then tamper with it
            var body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";
            var path = "/test";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Body(body)
                .Sign();

            // Tamper with the signature by replacing a character
            var tamperedSignature = tlSignature.Substring(0, tlSignature.Length - 5) + "XXXXX";

            Action verify = () => VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes(body),
                tamperedSignature
            );

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void LargePayload_ShouldWork()
        {
            // Test with a large payload that exceeds stackalloc threshold (>2KB)
            var largeBody = new string('x', 3000);
            var path = "/test/large";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path(path)
                .Body(largeBody)
                .Sign();

            VerifierSpan.VerifyWithPem(
                Encoding.UTF8.GetBytes(PublicKey),
                "POST",
                path,
                Array.Empty<KeyValuePair<string, byte[]>>(),
                Encoding.UTF8.GetBytes(largeBody),
                tlSignature
            ); // should not throw
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
#endif
