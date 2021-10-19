using System;
using System.Collections.Generic;
using System.Text;

namespace TrueLayer.Signing
{
    /// <summary>Sign/verification error.</summary>
    public sealed class SignatureException : Exception
    {
        internal static void Ensure(bool condition, string failMessage)
        {
            if (!condition)
            {
                throw new SignatureException(failMessage);
            }
        }

        /// <summary>
        /// Run the function converting any thrown exception into a SignatureException.
        /// </summary>
        internal static T Try<T>(Func<T> f, string? message = null)
        {
            try
            {
                return f();
            }
            catch (SignatureException)
            {
                throw;
            }
            catch (Exception e)
            {
                throw new SignatureException(message ?? e.Message ?? e.GetType().Name, e);
            }
        }

        internal SignatureException(string message) : base(message) { }
        internal SignatureException(string message, Exception? innerException) : base(message, innerException) { }
    }

    internal static class Util
    {
        /// <summary>
        /// Build signing payload from method, path, some/none/all headers and body.
        /// </summary>
        internal static byte[] BuildV2SigningPayload(
            string method,
            string path,
            List<(string, byte[])> headers,
            byte[] body)
        {
            var payload = new List<byte>();
            payload.AddRange(method.ToUpperInvariant().ToUtf8());
            payload.AddRange(" ".ToUtf8());
            payload.AddRange(path.ToUtf8());
            payload.AddRange("\n".ToUtf8());
            foreach (var (name, value) in headers)
            {
                payload.AddRange(name.ToUtf8());
                payload.AddRange(": ".ToUtf8());
                payload.AddRange(value);
                payload.AddRange("\n".ToUtf8());
            }
            payload.AddRange(body);
            return payload.ToArray();
        }

        /// <summary>Convert to utf-8 bytes</summary>
        internal static byte[] ToUtf8(this string text) => Encoding.UTF8.GetBytes(text);
    }

    /// <summary>Case-insensitive string header name comparison.</summary>
    internal class HeaderNameComparer : IEqualityComparer<string>
    {
        public bool Equals(string? x, string? y)
            => string.Equals(x, y, StringComparison.OrdinalIgnoreCase);

        public int GetHashCode(string x) => x.ToLowerInvariant().GetHashCode();
    }
}
