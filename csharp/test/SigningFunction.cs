using System;
using System.Security.Cryptography;
using System.Threading.Tasks;

namespace TrueLayer.Signing.Tests
{
    internal static class SigningFunction
    {
        public static Func<string, string> ForPrivateKey(string privateKeyPem) => payload =>
        {
            var privateKey = Util.ParsePem(privateKeyPem);
            var payloadBytes = System.Text.Encoding.UTF8.GetBytes(payload);
            var signatureBytes = privateKey.SignData(payloadBytes, HashAlgorithmName.SHA512);
            return Convert.ToBase64String(signatureBytes);
        };

        public static Func<string, Task<string>> ForPrivateKeyAsync(string privateKeyPem)
        {
            var func = ForPrivateKey(privateKeyPem);
            return payload => Task.FromResult(func(payload));
        }
    }
}