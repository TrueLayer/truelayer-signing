#if (NETSTANDARD2_0)

using System;
using System.IO;
using System.Security.Cryptography;
using Org.BouncyCastle.Crypto;
using Org.BouncyCastle.Crypto.Parameters;
using Org.BouncyCastle.OpenSsl;

namespace TrueLayer.Signing
{
    internal static class BouncyCastleUtil
    {
        internal static void BouncyCastleImportPem(this ECDsa key, ReadOnlySpan<char> pem)
        {
            var parameters = pem.ParseEcParameters();
            key.ImportParameters(parameters);
        }
        
        private static ECParameters ParseEcParameters(this ReadOnlySpan<char> pem)
        {
            var pemReader = new PemReader(new StringReader(pem.ToString()));
            var obj = pemReader.ReadObject();

            switch (obj)
            {
                case AsymmetricCipherKeyPair ecKeyPair:
                {
                    var privateKey = (ECPrivateKeyParameters) ecKeyPair.Private;
                    return privateKey.ParseEcParameters();
                }
                case ECPrivateKeyParameters privateKey:
                {
                    return privateKey.ParseEcParameters();
                }
                case ECPublicKeyParameters publicKey:
                {
                    return publicKey.ParseEcParameters();
                }
                default:
                {
                    throw new Exception($"Unexpected pem object {obj?.GetType().Name}");
                }
            }
        }

        private static ECParameters ParseEcParameters(this ECPrivateKeyParameters keyParams)
        {
            var normalizedPoint = keyParams.Parameters.G.Multiply(keyParams.D).Normalize();

            return new ECParameters
            {
                Curve = ECCurve.CreateFromValue(keyParams.PublicKeyParamSet.Id),
                D = keyParams.D.ToByteArrayUnsigned(),
                Q =
                {
                    X = normalizedPoint.XCoord.GetEncoded(),
                    Y = normalizedPoint.YCoord.GetEncoded()
                }
            };
        }

        private static ECParameters ParseEcParameters(this ECPublicKeyParameters keyParams)
        {
            return new ECParameters
            {
                Curve = ECCurve.CreateFromValue(keyParams.PublicKeyParamSet.Id),
                Q =
                {
                    X = keyParams.Q.XCoord.GetEncoded(),
                    Y = keyParams.Q.YCoord.GetEncoded(),
                }
            };
        }
    }
}

#endif