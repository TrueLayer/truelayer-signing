using Xunit;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using AwesomeAssertions;
using static TrueLayer.Signing.Tests.TestData;

namespace TrueLayer.Signing.Tests
{
    /// <summary>
    /// Comprehensive unit tests for custom JWS verification logic (VerifyJwsSignature and ParseJwsHeadersFromB64).
    /// These security-critical functions replaced the Jose.JWT library and require thorough testing.
    /// </summary>
    public class JwsVerificationTest
    {
        #region ParseJwsHeadersFromB64 Tests

        [Fact]
        public void ParseJwsHeaders_ValidHeader_ShouldSucceed()
        {
            // Valid JWS header with required fields - test that a properly signed request verifies
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Header("Idempotency-Key", "test-value")
                .Body("{}")
                .Sign();

            // Should not throw
            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Header("Idempotency-Key", "test-value")
                .Body("{}")
                .Verify(tlSignature);
        }

        [Fact]
        public void ParseJwsHeaders_EmptyHeader_ShouldFail()
        {
            // Empty string is not valid base64url
            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify("..");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void ParseJwsHeaders_InvalidBase64Url_ShouldFail()
        {
            // Invalid base64url characters
            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify("!!!invalid-base64!!..");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void ParseJwsHeaders_InvalidJson_ShouldFail()
        {
            // Valid base64url but invalid JSON
            var invalidJson = "not-json-at-all";
            var headerB64 = Base64Url.Encode(Encoding.UTF8.GetBytes(invalidJson));

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify($"{headerB64}..");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void ParseJwsHeaders_MalformedJson_ShouldFail()
        {
            // Malformed JSON (missing closing brace)
            var malformedJson = "{\"alg\":\"ES512\",\"kid\":\"test\"";
            var headerB64 = Base64Url.Encode(Encoding.UTF8.GetBytes(malformedJson));

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify($"{headerB64}..");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void ParseJwsHeaders_EmptyJsonObject_ShouldParseButFailValidation()
        {
            // Empty JSON object - parses but should fail validation (missing required fields)
            var emptyJson = "{}";
            var headerB64 = Base64Url.Encode(Encoding.UTF8.GetBytes(emptyJson));

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify($"{headerB64}..");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void ParseJwsHeaders_NullJsonObject_ShouldFail()
        {
            // JSON literal null
            var nullJson = "null";
            var headerB64 = Base64Url.Encode(Encoding.UTF8.GetBytes(nullJson));

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify($"{headerB64}..");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void ParseJwsHeaders_JsonArray_ShouldFail()
        {
            // JSON array instead of object
            var arrayJson = "[\"alg\",\"ES512\"]";
            var headerB64 = Base64Url.Encode(Encoding.UTF8.GetBytes(arrayJson));

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify($"{headerB64}..");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void ParseJwsHeaders_Base64UrlPaddingVariations_ShouldSucceed()
        {
            // Test various padding scenarios in base64url encoding
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            // Signature should work regardless of padding
            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify(tlSignature);
        }

        #endregion

        #region VerifyJwsSignature Tests - Malformed Tokens

        [Fact]
        public void VerifyJws_MissingSignaturePart_ShouldFail()
        {
            // JWS with empty signature part
            var headerDict = new Dictionary<string, object>
            {
                ["alg"] = "ES512",
                ["kid"] = Kid,
                ["tl_version"] = "2",
                ["tl_headers"] = ""
            };
            var headerB64 = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(headerDict));

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify($"{headerB64}..");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_InvalidSignatureBase64_ShouldFail()
        {
            // Invalid base64url in signature part
            var headerDict = new Dictionary<string, object>
            {
                ["alg"] = "ES512",
                ["kid"] = Kid,
                ["tl_version"] = "2",
                ["tl_headers"] = ""
            };
            var headerB64 = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(headerDict));

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify($"{headerB64}..!!!invalid!!!");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_WrongSignatureLength_ShouldFail()
        {
            // ES512 signatures should be 132 bytes (IEEE P1363 format)
            // Test with wrong length signature
            var headerDict = new Dictionary<string, object>
            {
                ["alg"] = "ES512",
                ["kid"] = Kid,
                ["tl_version"] = "2",
                ["tl_headers"] = ""
            };
            var headerB64 = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(headerDict));

            // Create a signature that's too short
            var shortSignature = Base64Url.Encode(new byte[64]); // Should be 132 bytes for ES512

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify($"{headerB64}..{shortSignature}");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_AllZeroSignature_ShouldFail()
        {
            // Valid length but all zeros (invalid signature)
            var headerDict = new Dictionary<string, object>
            {
                ["alg"] = "ES512",
                ["kid"] = Kid,
                ["tl_version"] = "2",
                ["tl_headers"] = ""
            };
            var headerB64 = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(headerDict));
            var zeroSignature = Base64Url.Encode(new byte[132]);

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify($"{headerB64}..{zeroSignature}");

            verify.Should().Throw<SignatureException>();
        }

        #endregion

        #region VerifyJwsSignature Tests - Tampered Signatures

        [Fact]
        public void VerifyJws_TamperedSignatureLastByte_ShouldFail()
        {
            // Sign normally, then tamper with the signature
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{\"test\":\"data\"}")
                .Sign();

            // Tamper with the signature by flipping the last byte
            var parts = tlSignature.Split('.');
            var signatureBytes = Base64Url.Decode(parts[2]);
            signatureBytes[signatureBytes.Length - 1] ^= 0xFF; // Flip all bits in last byte
            var tamperedSignature = Base64Url.Encode(signatureBytes);

            var tamperedJws = $"{parts[0]}..{tamperedSignature}";

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{\"test\":\"data\"}")
                .Verify(tamperedJws);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_TamperedSignatureFirstByte_ShouldFail()
        {
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            var parts = tlSignature.Split('.');
            var signatureBytes = Base64Url.Decode(parts[2]);
            signatureBytes[0] ^= 0x01; // Flip one bit in first byte
            var tamperedSignature = Base64Url.Encode(signatureBytes);

            var tamperedJws = $"{parts[0]}..{tamperedSignature}";

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify(tamperedJws);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_TamperedSignatureMiddleByte_ShouldFail()
        {
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            var parts = tlSignature.Split('.');
            var signatureBytes = Base64Url.Decode(parts[2]);
            signatureBytes[signatureBytes.Length / 2] ^= 0x01;
            var tamperedSignature = Base64Url.Encode(signatureBytes);

            var tamperedJws = $"{parts[0]}..{tamperedSignature}";

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify(tamperedJws);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_SwappedRAndSComponents_ShouldFail()
        {
            // ES512 signature is r||s (each 66 bytes)
            // Swapping them should fail verification
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            var parts = tlSignature.Split('.');
            var signatureBytes = Base64Url.Decode(parts[2]);

            // Swap r and s components
            var r = new byte[66];
            var s = new byte[66];
            Array.Copy(signatureBytes, 0, r, 0, 66);
            Array.Copy(signatureBytes, 66, s, 0, 66);

            var swapped = new byte[132];
            Array.Copy(s, 0, swapped, 0, 66);
            Array.Copy(r, 0, swapped, 66, 66);

            var swappedSignature = Base64Url.Encode(swapped);
            var tamperedJws = $"{parts[0]}..{swappedSignature}";

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify(tamperedJws);

            verify.Should().Throw<SignatureException>();
        }

        #endregion

        #region VerifyJwsSignature Tests - Tampered Headers

        [Fact]
        public void VerifyJws_TamperedHeaderAlg_ShouldFail()
        {
            // Create a valid signature, then change the algorithm in the header
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            var parts = tlSignature.Split('.');
            var headerBytes = Base64Url.Decode(parts[0]);
            var headerDict = JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes);

            // Change algorithm
            if (headerDict != null)
            {
                headerDict["alg"] = "ES256";
                var tamperedHeaderB64 = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(headerDict));
                var tamperedJws = $"{tamperedHeaderB64}..{parts[2]}";

                Action verify = () => Verifier.VerifyWithPem(PublicKey)
                    .Method("POST")
                    .Path("/test")
                    .Body("{}")
                    .Verify(tamperedJws);

                verify.Should().Throw<SignatureException>();
            }
        }

        [Fact]
        public void VerifyJws_TamperedHeaderKid_ShouldFail()
        {
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            var parts = tlSignature.Split('.');
            var headerBytes = Base64Url.Decode(parts[0]);
            var headerDict = JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes);

            if (headerDict != null)
            {
                headerDict["kid"] = "different-kid";
                var tamperedHeaderB64 = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(headerDict));
                var tamperedJws = $"{tamperedHeaderB64}..{parts[2]}";

                Action verify = () => Verifier.VerifyWithPem(PublicKey)
                    .Method("POST")
                    .Path("/test")
                    .Body("{}")
                    .Verify(tamperedJws);

                verify.Should().Throw<SignatureException>();
            }
        }

        [Fact]
        public void VerifyJws_TamperedHeaderTlHeaders_ShouldFail()
        {
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Header("X-Custom", "value")
                .Body("{}")
                .Sign();

            var parts = tlSignature.Split('.');
            var headerBytes = Base64Url.Decode(parts[0]);
            var headerDict = JsonSerializer.Deserialize<Dictionary<string, object>>(headerBytes);

            if (headerDict != null)
            {
                // Remove a header from tl_headers
                headerDict["tl_headers"] = "";
                var tamperedHeaderB64 = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(headerDict));
                var tamperedJws = $"{tamperedHeaderB64}..{parts[2]}";

                Action verify = () => Verifier.VerifyWithPem(PublicKey)
                    .Method("POST")
                    .Path("/test")
                    .Header("X-Custom", "value")
                    .Body("{}")
                    .Verify(tamperedJws);

                verify.Should().Throw<SignatureException>();
            }
        }

        #endregion

        #region VerifyJwsSignature Tests - Invalid Hash

        [Fact]
        public void VerifyJws_SignatureForDifferentPayload_ShouldFail()
        {
            // Sign one payload, verify with a different one
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{\"original\":\"payload\"}")
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{\"tampered\":\"payload\"}") // Different payload
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_SignatureForDifferentMethod_ShouldFail()
        {
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("GET") // Different method
                .Path("/test")
                .Body("{}")
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_SignatureForDifferentPath_ShouldFail()
        {
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/original")
                .Body("{}")
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/tampered") // Different path
                .Body("{}")
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_SignatureForDifferentHeaders_ShouldFail()
        {
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Header("X-Custom", "original")
                .Body("{}")
                .Sign();

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Header("X-Custom", "tampered") // Different header value
                .Body("{}")
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        #endregion

        #region VerifyJwsSignature Tests - Edge Cases

        [Fact]
        public void VerifyJws_EmptyPayload_ShouldSucceed()
        {
            // Valid signature with empty payload
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("GET")
                .Path("/test")
                .Body("")
                .Sign();

            Verifier.VerifyWithPem(PublicKey)
                .Method("GET")
                .Path("/test")
                .Body("")
                .Verify(tlSignature); // Should not throw
        }

        [Fact]
        public void VerifyJws_LargePayload_ShouldSucceed()
        {
            // Test with a large payload
            var largePayload = new string('x', 100000);

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body(largePayload)
                .Sign();

            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body(largePayload)
                .Verify(tlSignature); // Should not throw
        }

        [Fact]
        public void VerifyJws_UnicodeInPayload_ShouldSucceed()
        {
            // Test with Unicode characters
            var unicodePayload = "{\"message\":\"Hello 世界 🌍\"}";

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body(unicodePayload)
                .Sign();

            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body(unicodePayload)
                .Verify(tlSignature); // Should not throw
        }

        [Fact]
        public void VerifyJws_BinaryPayload_ShouldSucceed()
        {
            // Test with binary data (not valid UTF-8)
            var binaryPayload = new byte[] { 0x00, 0xFF, 0xFE, 0xFD, 0xAA, 0x55 };

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body(binaryPayload)
                .Sign();

            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body(binaryPayload)
                .Verify(tlSignature); // Should not throw
        }

        [Fact]
        public void VerifyJws_MultipleConcurrentVerifications_ShouldSucceed()
        {
            // Test thread-safety by performing multiple verifications
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            // Each verification should succeed independently
            for (int i = 0; i < 10; i++)
            {
                Verifier.VerifyWithPem(PublicKey)
                    .Method("POST")
                    .Path("/test")
                    .Body("{}")
                    .Verify(tlSignature); // Should not throw
            }
        }

        [Fact]
        public void VerifyJws_WrongPublicKey_ShouldFail()
        {
            // Sign with one key, verify with another
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            // Use a different public key
            var wrongPublicKey = BugReproduction.LengthError.PublicKey;

            Action verify = () => Verifier.VerifyWithPem(wrongPublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void ExtractKid_ValidSignature_ShouldSucceed()
        {
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Sign();

            var extractedKid = Verifier.ExtractKid(tlSignature);
            extractedKid.Should().Be(Kid);
        }

        [Fact]
        public void ExtractKid_MissingKid_ShouldFail()
        {
            // Create a signature without kid
            var headerDict = new Dictionary<string, object>
            {
                ["alg"] = "ES512",
                ["tl_version"] = "2",
                ["tl_headers"] = ""
            };
            var headerB64 = Base64Url.Encode(JsonSerializer.SerializeToUtf8Bytes(headerDict));

            Action extract = () => Verifier.ExtractKid($"{headerB64}..signature");

            extract.Should().Throw<SignatureException>();
        }

        [Fact]
        public void ExtractKid_MalformedJws_ShouldFail()
        {
            Action extract = () => Verifier.ExtractKid("not-a-valid-jws");

            extract.Should().Throw<SignatureException>();
        }

        #endregion

        #region Cross-cutting Security Tests

        [Fact]
        public void VerifyJws_ReplayAttack_DifferentContext_ShouldFail()
        {
            // Sign a request for one endpoint
            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("DELETE")
                .Path("/users/123")
                .Body("{}")
                .Sign();

            // Try to replay on a different endpoint
            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("DELETE")
                .Path("/users/456") // Different user ID
                .Body("{}")
                .Verify(tlSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void VerifyJws_NullByteInPayload_ShouldHandle()
        {
            // Test with null bytes in payload
            var payloadWithNull = new byte[] { 0x7B, 0x00, 0x7D }; // {, null, }

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Body(payloadWithNull)
                .Sign();

            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body(payloadWithNull)
                .Verify(tlSignature); // Should not throw
        }

        [Fact]
        public void VerifyJws_ExtremelyLongHeader_ShouldHandle()
        {
            // Test with a very long header value
            var longValue = new string('x', 10000);

            var tlSignature = Signer.SignWithPem(Kid, PrivateKey)
                .Method("POST")
                .Path("/test")
                .Header("X-Long-Header", longValue)
                .Body("{}")
                .Sign();

            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Header("X-Long-Header", longValue)
                .Body("{}")
                .Verify(tlSignature); // Should not throw
        }

        #endregion
    }
}
