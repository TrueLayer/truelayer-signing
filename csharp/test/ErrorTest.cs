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
        public void MissingJwsHeaders()
        {
            // jws headers are lacking bits we need
            const string Signature = "eyJhbGciOiJFUzUxMiIsImtpZCI6IjQ1ZmM3NWNmLTU2ND"
                + "ktNDEzNC04NGIzLTE5MmMyYzc4ZTk5MCIsInRsX2hlYWRlcnMiOiIifQ..AHrNENw"
                + "CMqQ_kDEQZiXeXsLxgXCDn-62b_Oh1yEPKsE8n1-qC3EIpA360WeCJXMyeMVH3FKi"
                + "aJ1A1px7AnmzUIpeATgzbPSlWjyB-q2e--XeyOhausFq0BCWWfHbhlyGkjfk9zkBq"
                + "XXd2iibbLPvId-tL50UhNBKNse_EMoKsW_Lav7D";

            Action verify = () => Verifier.VerifyWithPem(PublicKey)
                .Method("POST")
                .Path("/foo")
                .Body("{}")
                .Verify(Signature);

            verify.Should().Throw<SignatureException>();
        }
    }
}
