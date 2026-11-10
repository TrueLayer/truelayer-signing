using Xunit;
using System;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using AwesomeAssertions;
using static TrueLayer.Signing.Tests.TestData;

namespace TrueLayer.Signing.Tests
{
    public class DigestFunctionSignerTest
    {
        private const string Path = "/merchant_accounts/a61acaef-ee05-4077-92f3-25543a11bd8d/sweeping";
        private const string IdempotencyKey = "idemp-2076717c-9005-4811-a321-9e0787fa0382";

        // signs a digest the way a KMS would: P1363 signature over the given SHA-512 digest
        private static Func<byte[], Task<string>> DigestSigner(string privateKeyPem) => digest =>
        {
            using var key = Util.ParsePem(privateKeyPem);
            return Task.FromResult(Base64Url.Encode(key.SignHash(digest)));
        };

        [Theory]
        [MemberData(nameof(UsageTest.TestCases), MemberType = typeof(UsageTest))]
        public async Task SignWithDigestFunction_ProducesSignatureThatVerifies(UsageTest.TestCase testCase)
        {
            const string body = "{\"currency\":\"GBP\",\"max_amount_in_minor\":5000000}";

            var tlSignature = await Signer.SignWithDigestFunction(testCase.Kid, DigestSigner(testCase.PrivateKey))
                .Method("POST")
                .Path(Path)
                .Header("Idempotency-Key", IdempotencyKey)
                .Body(body)
                .SignAsync();

            Verifier.VerifyWithPem(testCase.PublicKey)
                .Method("POST")
                .Path(Path)
                .Header("Idempotency-Key", IdempotencyKey)
                .Body(body)
                .Verify(tlSignature); // should not throw
        }

        [Theory]
        [InlineData(0)]
        [InlineData(1)]
        [InlineData(2)]
        [InlineData(3)]
        [InlineData(4)]
        [InlineData(1000)]
        public async Task SignWithDigestFunction_DigestMatchesSignWithFunctionMessage(int bodyLength)
        {
            // multi-byte characters, and lengths covering every base64 padding case
            var body = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("é€", bodyLength)));

            string? message = null;
            await Signer.SignWithFunction(Kid, m =>
                {
                    message = m;
                    return Task.FromResult("sig");
                })
                .Method("POST")
                .Path(Path)
                .Header("Idempotency-Key", IdempotencyKey)
                .Body(body)
                .SignAsync();

            byte[]? digest = null;
            await Signer.SignWithDigestFunction(Kid, d =>
                {
                    digest = d;
                    return Task.FromResult("sig");
                })
                .Method("POST")
                .Path(Path)
                .Header("Idempotency-Key", IdempotencyKey)
                .Body(body)
                .SignAsync();

            using var sha512 = SHA512.Create();
            digest.Should().Equal(sha512.ComputeHash(Encoding.UTF8.GetBytes(message!)));
        }

        [Fact]
        public async Task SignWithDigestFunction_ReturnsDetachedJws()
        {
            var tlSignature = await Signer.SignWithDigestFunction(Kid, _ => Task.FromResult("the-signature"))
                .Method("POST")
                .Path(Path)
                .SignAsync();

            var parts = tlSignature.Split('.');
            parts.Should().HaveCount(3);
            parts[1].Should().BeEmpty();
            parts[2].Should().Be("the-signature");
        }
    }
}
