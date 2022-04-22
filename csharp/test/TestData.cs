using System.IO;

namespace TrueLayer.Signing.Tests
{
    internal static class TestData
    {
        public const string Kid = "45fc75cf-5649-4134-84b3-192c2c78e990";
        public static string PrivateKey { get; } = File.ReadAllText(TestResourcePath("ec512-private.pem"));
        public static string PublicKey { get; } = File.ReadAllText(TestResourcePath("ec512-public.pem"));

        /// <summary>Return working path to /test-resources/$subpath</summary>
        public static string TestResourcePath(string subpath)
            => Path.Combine("../../../../../test-resources", subpath);

        public static class BugReproduction
        {
            public static class LengthError
            {
                public const string Kid = "09ca8d16-bff8-4dbf-ba0b-2fc4dbaed7cc";
                public static string PrivateKey { get; } = File.ReadAllText(TestResourcePath("ec512-private.pem"));
                public static string PublicKey { get; } = File.ReadAllText(TestResourcePath("ec512-public.pem"));

                public static string TestResourcePath(string subpath)
                    => Path.Combine(BugReproduction.TestResourcePath("./LengthError"), subpath);
            }

            public static string TestResourcePath(string subpath)
                => Path.Combine("./BugReproduction", subpath);
        }
    }
}