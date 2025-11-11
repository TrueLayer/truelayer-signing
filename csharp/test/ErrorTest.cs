using Xunit;
using System;
using AwesomeAssertions;
using Jose;
using System.Text;
using System.Collections.Generic;
using System.Text.Json;
using System.Linq;

using static TrueLayer.Signing.Tests.TestData;

namespace TrueLayer.Signing.Tests
{
    public class ErrorTest
    {
        [Fact]
        public void BadKey()
        {
            Action sign = () => Signer.SignWithPem(Kid, "not-a-key");
            sign.Should().Throw<ArgumentException>();

            Action verify = () => Verifier.VerifyWithPem("also-not-a-key");
            verify.Should().Throw<ArgumentException>();
        }

        [Fact]
        public void BagSignature()
        {
            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("post")
                .Path("/foo")
                .Body("{}")
                .Verify("not-a-signature");

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void InvalidButPreAttachedJwsBody()
        {
            // signature for `/bar` but with a valid jws-body pre-attached
            // if we run verify on this unchanged it'll work!
            const string Signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
                + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV"
                + "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
                + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
                + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
                + "d2d3D17Wd9UA";

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("post")
                .Path("/foo") // not /bar so should fail
                .Body("{}")
                .Verify(Signature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void InvalidButPreAttachedJwsBodyTrailingDots()
        {
            // signature for `/bar` but with a valid jws-body pre-attached
            // if we run verify on this unchanged it'll work!
            const string Signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
                + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX3ZlcnNpb24iOiIyIiwidGxfaGV"
                + "hZGVycyI6IiJ9.UE9TVCAvYmFyCnt9.ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
                + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
                + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
                + "d2d3D17Wd9UA....";

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("post")
                .Path("/foo") // not /bar so should fail
                .Body("{}")
                .Verify(Signature);

            verify.Should().Throw<SignatureException>();
        }

        [Theory]
        [InlineData("alg")]
        [InlineData("kid")]
        [InlineData("tl_version")]
        public void MissingJwsHeaders(string sansHeader)
        {
            // creates a (POST /bar {}) signature with custom jwsHeaderMap
            string CreateSignature(Dictionary<string, string> jwsHeaderMap)
            {
                var signature = Signer.SignWithPem(Kid, PrivateKey)
                    .Method("POST")
                    .Path("/bar")
                    .Body("{}")
                    .Sign();

                var jwsEncoded = Base64Url.Encode(
                    Encoding.UTF8.GetBytes(JsonSerializer.Serialize(jwsHeaderMap)));

                return $"{jwsEncoded}..{signature.Split(".").Last()}";
            }

            var jwsHeaderMap = new Dictionary<string, string>()
            {
                {"alg", "ES512"},
                {"kid", Kid},
                {"tl_version", "2"},
                {"tl_headers", ""},
            };

            var goodSignature = CreateSignature(jwsHeaderMap);

            // signature is valid with all required jws headers
            Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/bar")
                .Body("{}")
                .Verify(goodSignature); // should not throw

            // if we remove a required header verify should fail
            jwsHeaderMap.Remove(sansHeader).Should()
                .BeTrue($"jwsHeaderMap didn't contain {sansHeader}");

            var badSignature = CreateSignature(jwsHeaderMap);

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/bar")
                .Body("{}")
                .Verify(badSignature);

            verify.Should().Throw<SignatureException>();
        }

        [Fact]
        public void InvalidSignerPath()
        {
            Action sign = () => Signer.SignWithPem(Kid, PrivateKey)
                .Path("https://example.com/the-path");

            sign.Should().Throw<ArgumentException>()
                .WithMessage("Invalid path \"https://example.com/the-path\" must start with '/'");
        }

        [Fact]
        public void InvalidVerifierPath()
        {
            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Path("https://example.com/the-path");

            verify.Should().Throw<ArgumentException>()
                .WithMessage("Invalid path \"https://example.com/the-path\" must start with '/'");
        }

        [Theory]
        [InlineData("nodots")]
        [InlineData("one.dot")]
        [InlineData("too.many.dots.here")]
        [InlineData("header..signature....")]
        public void InvalidSignatureFormat(string invalidSignature)
        {
            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/test")
                .Body("{}")
                .Verify(invalidSignature);

            verify.Should().Throw<SignatureException>()
                .WithMessage("invalid signature format, expected detached JWS (header..signature)");
        }
    }
}
