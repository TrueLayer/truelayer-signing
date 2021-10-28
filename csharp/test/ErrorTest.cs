using Xunit;
using TrueLayer.Signing;
using System;
using FluentAssertions;

namespace Tests
{
    public class ErrorTest
    {
        private const string PublicKey = UsageTest.PublicKey;
        private const string PrivateKey = UsageTest.PrivateKey;
        private const string Kid = UsageTest.Kid;

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
    }
}
