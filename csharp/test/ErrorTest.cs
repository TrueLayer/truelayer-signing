using Xunit;
using TrueLayer.Signing;
using System;
using FluentAssertions;
using Jose;
using System.Text;
using System.Collections.Generic;
using System.Text.Json;

namespace Tests
{
    public class ErrorTest
    {
        private const string Kid = UsageTest.Kid;
        private static string PublicKey = UsageTest.PublicKey;
        private static string PrivateKey = UsageTest.PrivateKey;

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
            // creates a (POST /bar {}) signature
            string CreateSignature(Dictionary<string, string> jwsHeaderMap)
            {
                var jwsEncoded = Base64Url.Encode(
                    Encoding.UTF8.GetBytes(JsonSerializer.Serialize(jwsHeaderMap)));

                return $"{jwsEncoded}..ARLa7Q5b8k5CIhfy1qrS-IkNqCDeE-VFRD"
                    + "z7Lb0fXUMOi_Ktck-R7BHDMXFDzbI5TyaxIo5TGHZV_cs0fg96dlSxAERp3UaN2oC"
                    + "QHIE5gQ4m5uU3ee69XfwwU_RpEIMFypycxwq1HOf4LzTLXqP_CDT8DdyX8oTwYdUB"
                    + "d2d3D17Wd9UA";
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
    }
}
