using System.IO;

namespace TrueLayer.Signing.Tests
{
    internal static class TestData
    {
        public const string Kid = "45fc75cf-5649-4134-84b3-192c2c78e990";
        public static string PrivateKey { get; } = File.ReadAllText(TestResourcePath("ec512-private.pem"));
        public static string PublicKey { get; }  = File.ReadAllText(TestResourcePath("ec512-public.pem"));

        /// <summary>Return working path to /test-resources/$subpath</summary>
        public static string TestResourcePath(string subpath)
            => Path.Combine("../../../../../test-resources", subpath);
    }
}