using Xunit;
using System;
using System.Text;
using AwesomeAssertions;

namespace TrueLayer.Signing.Tests
{
    /// <summary>
    /// Comprehensive unit tests for the custom Base64Url encoding/decoding implementation.
    /// This is a security-critical component that replaced standard library functionality for AOT compatibility.
    /// </summary>
    public class Base64UrlTest
    {
        #region Encode Tests

        [Fact]
        public void Encode_EmptyInput_ShouldReturnEmptyString()
        {
            var input = Array.Empty<byte>();
            var result = Base64Url.Encode(input);
            result.Should().Be("");
        }

        [Fact]
        public void Encode_SingleByte_ShouldEncode()
        {
            var input = new byte[] { 0xFF };
            var result = Base64Url.Encode(input);

            // Standard base64 would be "_w==" but base64url removes padding
            result.Should().Be("_w");
        }

        [Fact]
        public void Encode_TwoBytes_ShouldEncode()
        {
            var input = new byte[] { 0xFF, 0xFE };
            var result = Base64Url.Encode(input);

            // Standard base64 would be "__4=" but base64url removes padding
            result.Should().Be("__4");
        }

        [Fact]
        public void Encode_ThreeBytes_ShouldEncodeWithoutPadding()
        {
            var input = new byte[] { 0xFF, 0xFE, 0xFD };
            var result = Base64Url.Encode(input);

            // Standard base64 would be "__79" (no padding needed)
            result.Should().Be("__79");
        }

        [Fact]
        public void Encode_FourBytes_ShouldEncode()
        {
            var input = new byte[] { 0xFF, 0xFE, 0xFD, 0xFC };
            var result = Base64Url.Encode(input);

            // Length % 4 == 0, should have no padding
            result.Should().NotContain("=");
        }

        [Fact]
        public void Encode_PaddingLength1_ShouldRemovePadding()
        {
            // Input length that results in 1 padding character
            var input = new byte[] { 0x61, 0x62, 0x63, 0x64, 0x65 }; // "abcde"
            var result = Base64Url.Encode(input);

            // Standard base64: "YWJjZGU="
            // Base64url: "YWJjZGU"
            result.Should().NotContain("=");
            result.Should().Be("YWJjZGU");
        }

        [Fact]
        public void Encode_PaddingLength2_ShouldRemovePadding()
        {
            // Input length that results in 2 padding characters
            var input = new byte[] { 0x61, 0x62, 0x63, 0x64 }; // "abcd"
            var result = Base64Url.Encode(input);

            // Standard base64: "YWJjZA=="
            // Base64url: "YWJjZA"
            result.Should().NotContain("=");
            result.Should().Be("YWJjZA");
        }

        [Fact]
        public void Encode_WithPlus_ShouldReplaceWithDash()
        {
            // Crafted input that produces '+' in standard base64
            // 0x03 0xE3 produces "A+M=" in standard base64
            var input = new byte[] { 0x03, 0xE3 };
            var result = Base64Url.Encode(input);

            result.Should().NotContain("+");
            result.Should().Contain("-");
            result.Should().Be("A-M");
        }

        [Fact]
        public void Encode_WithSlash_ShouldReplaceWithUnderscore()
        {
            // Crafted input that produces '/' in standard base64
            // 0xFF produces "_w==" in base64url
            var input = new byte[] { 0xFF };
            var result = Base64Url.Encode(input);

            result.Should().NotContain("/");
            result.Should().Contain("_");
        }

        [Fact]
        public void Encode_AllPossibleBytes_ShouldNotContainPaddingOrSpecialChars()
        {
            // Test with all byte values 0-255
            var input = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                input[i] = (byte)i;
            }

            var result = Base64Url.Encode(input);

            result.Should().NotContain("=");
            result.Should().NotContain("+");
            result.Should().NotContain("/");
        }

        [Fact]
        public void Encode_SimpleText_ShouldEncodeCorrectly()
        {
            var input = Encoding.UTF8.GetBytes("Hello World");
            var result = Base64Url.Encode(input);

            // Standard base64: "SGVsbG8gV29ybGQ="
            // Base64url: "SGVsbG8gV29ybGQ"
            result.Should().Be("SGVsbG8gV29ybGQ");
        }

        [Fact]
        public void Encode_JsonPayload_ShouldEncodeCorrectly()
        {
            var input = Encoding.UTF8.GetBytes("{\"test\":\"data\"}");
            var result = Base64Url.Encode(input);

            result.Should().NotContain("=");
            result.Should().NotContain("+");
            result.Should().NotContain("/");
        }

        [Fact]
        public void Encode_BinaryData_ShouldHandle()
        {
            var input = new byte[] { 0x00, 0x01, 0x02, 0x03, 0xFD, 0xFE, 0xFF };
            var result = Base64Url.Encode(input);

            result.Should().NotContain("=");
            result.Should().NotBeEmpty();
        }

        [Fact]
        public void Encode_LargeInput_ShouldHandle()
        {
            var input = new byte[10000];
            new Random(42).NextBytes(input);

            var result = Base64Url.Encode(input);

            result.Should().NotContain("=");
            result.Should().NotContain("+");
            result.Should().NotContain("/");
            result.Length.Should().BeGreaterThan(0);
        }

        #endregion

        #region Decode Tests

        [Fact]
        public void Decode_EmptyInput_ShouldReturnEmptyArray()
        {
            var result = Base64Url.Decode("");
            result.Should().NotBeNull();
            result.Length.Should().Be(0);
        }

        [Fact]
        public void Decode_WithoutPadding_Length2_ShouldDecode()
        {
            // "YQ" without padding should decode to "a"
            var result = Base64Url.Decode("YQ");
            result.Should().Equal(new byte[] { 0x61 }); // 'a'
        }

        [Fact]
        public void Decode_WithoutPadding_Length3_ShouldDecode()
        {
            // "YWI" without padding should decode to "ab"
            var result = Base64Url.Decode("YWI");
            result.Should().Equal(new byte[] { 0x61, 0x62 }); // 'ab'
        }

        [Fact]
        public void Decode_WithoutPadding_Length4Multiple_ShouldDecode()
        {
            // "AQID" is length 4 (no padding needed)
            var result = Base64Url.Decode("AQID");
            result.Should().Equal(new byte[] { 0x01, 0x02, 0x03 });
        }

        [Fact]
        public void Decode_WithDash_ShouldDecodeAsPlus()
        {
            // "A-M" should decode same as "A+M=" in standard base64
            var result = Base64Url.Decode("A-M");
            result.Should().Equal(new byte[] { 0x03, 0xE3 });
        }

        [Fact]
        public void Decode_WithUnderscore_ShouldDecodeAsSlash()
        {
            // "_w" should decode same as "/w==" in standard base64
            var result = Base64Url.Decode("_w");
            result.Should().Equal(new byte[] { 0xFF });
        }

        [Fact]
        public void Decode_MultipleUnderscoresAndDashes_ShouldDecode()
        {
            // Base64url with both special characters
            var input = "A-M_";
            var result = Base64Url.Decode(input);
            result.Should().NotBeNull();
            result.Length.Should().BeGreaterThan(0);
        }

        [Fact]
        public void Decode_SimpleText_ShouldDecodeCorrectly()
        {
            var result = Base64Url.Decode("SGVsbG8gV29ybGQ");
            var decoded = Encoding.UTF8.GetString(result);
            decoded.Should().Be("Hello World");
        }

        [Fact]
        public void Decode_PaddingLength1_ShouldAddPadding()
        {
            // "YWJjZGU" -> needs 1 '=' to be valid base64
            var result = Base64Url.Decode("YWJjZGU");
            var decoded = Encoding.UTF8.GetString(result);
            decoded.Should().Be("abcde");
        }

        [Fact]
        public void Decode_PaddingLength2_ShouldAddPadding()
        {
            // "YWJjZA" -> needs 2 '==' to be valid base64
            var result = Base64Url.Decode("YWJjZA");
            var decoded = Encoding.UTF8.GetString(result);
            decoded.Should().Be("abcd");
        }

        [Fact]
        public void Decode_AllBase64UrlAlphabet_ShouldDecode()
        {
            // Test string containing all valid base64url characters
            var input = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            var result = Base64Url.Decode(input);
            result.Should().NotBeNull();
            result.Length.Should().BeGreaterThan(0);
        }

        [Fact]
        public void Decode_InvalidBase64_ShouldThrow()
        {
            // Invalid base64 characters
            Action decode = () => Base64Url.Decode("!!!invalid!!!");
            decode.Should().Throw<FormatException>();
        }

        [Fact]
        public void Decode_WithWhitespace_ShouldThrow()
        {
            // Base64 with whitespace (not valid base64url)
            Action decode = () => Base64Url.Decode("SGVs bG8");
            decode.Should().Throw<FormatException>();
        }

        [Fact]
        public void Decode_BinaryData_ShouldDecode()
        {
            // Encoded binary data
            var encoded = "AAECAw";
            var result = Base64Url.Decode(encoded);
            result.Should().Equal(new byte[] { 0x00, 0x01, 0x02, 0x03 });
        }

        #endregion

        #region Round-trip Tests

        [Fact]
        public void RoundTrip_EmptyArray_ShouldMatch()
        {
            var original = Array.Empty<byte>();
            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);
            decoded.Should().Equal(original);
        }

        [Fact]
        public void RoundTrip_SingleByte_ShouldMatch()
        {
            var original = new byte[] { 0x42 };
            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);
            decoded.Should().Equal(original);
        }

        [Fact]
        public void RoundTrip_TwoBytes_ShouldMatch()
        {
            var original = new byte[] { 0x42, 0x43 };
            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);
            decoded.Should().Equal(original);
        }

        [Fact]
        public void RoundTrip_ThreeBytes_ShouldMatch()
        {
            var original = new byte[] { 0x42, 0x43, 0x44 };
            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);
            decoded.Should().Equal(original);
        }

        [Fact]
        public void RoundTrip_FourBytes_ShouldMatch()
        {
            var original = new byte[] { 0x42, 0x43, 0x44, 0x45 };
            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);
            decoded.Should().Equal(original);
        }

        [Fact]
        public void RoundTrip_AllPaddingLengths_ShouldMatch()
        {
            // Test all possible padding scenarios (length % 4 == 0, 1, 2, 3)
            for (int length = 0; length < 20; length++)
            {
                var original = new byte[length];
                for (int i = 0; i < length; i++)
                {
                    original[i] = (byte)(i % 256);
                }

                var encoded = Base64Url.Encode(original);
                var decoded = Base64Url.Decode(encoded);

                decoded.Should().Equal(original, $"Round-trip failed for length {length}");
            }
        }

        [Fact]
        public void RoundTrip_AllByteValues_ShouldMatch()
        {
            // Test with all possible byte values
            var original = new byte[256];
            for (int i = 0; i < 256; i++)
            {
                original[i] = (byte)i;
            }

            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);

            decoded.Should().Equal(original);
        }

        [Fact]
        public void RoundTrip_RandomData_ShouldMatch()
        {
            var random = new Random(42);

            for (int i = 0; i < 100; i++)
            {
                var length = random.Next(0, 1000);
                var original = new byte[length];
                random.NextBytes(original);

                var encoded = Base64Url.Encode(original);
                var decoded = Base64Url.Decode(encoded);

                decoded.Should().Equal(original, $"Round-trip failed for random data iteration {i}");
            }
        }

        [Fact]
        public void RoundTrip_Utf8Text_ShouldMatch()
        {
            var texts = new[]
            {
                "",
                "a",
                "ab",
                "abc",
                "abcd",
                "Hello World",
                "The quick brown fox jumps over the lazy dog",
                "{\"key\":\"value\"}",
                "Unicode: 你好世界 🌍",
                "Special chars: !@#$%^&*()_+-=[]{}|;':\",./<>?"
            };

            foreach (var text in texts)
            {
                var original = Encoding.UTF8.GetBytes(text);
                var encoded = Base64Url.Encode(original);
                var decoded = Base64Url.Decode(encoded);

                decoded.Should().Equal(original, $"Round-trip failed for text: {text}");
                Encoding.UTF8.GetString(decoded).Should().Be(text);
            }
        }

        [Fact]
        public void RoundTrip_LargeData_ShouldMatch()
        {
            var original = new byte[100000];
            new Random(42).NextBytes(original);

            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);

            decoded.Should().Equal(original);
        }

        [Fact]
        public void RoundTrip_BinaryWithNulls_ShouldMatch()
        {
            var original = new byte[] { 0x00, 0xFF, 0x00, 0xFF, 0x00 };
            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);
            decoded.Should().Equal(original);
        }

        [Fact]
        public void RoundTrip_JsonPayload_ShouldMatch()
        {
            var json = "{\"alg\":\"ES512\",\"kid\":\"test-key\",\"tl_version\":\"2\"}";
            var original = Encoding.UTF8.GetBytes(json);
            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);

            decoded.Should().Equal(original);
            Encoding.UTF8.GetString(decoded).Should().Be(json);
        }

        #endregion

        #region Edge Cases and Security Tests

        [Fact]
        public void Encode_NullArray_ShouldThrow()
        {
            Action encode = () => Base64Url.Encode(null!);
            encode.Should().Throw<ArgumentNullException>();
        }

        [Fact]
        public void Decode_NullString_ShouldThrow()
        {
            Action decode = () => Base64Url.Decode(null!);
            // The current implementation throws NullReferenceException
            decode.Should().Throw<Exception>();
        }

        [Fact]
        public void Decode_WithStandardBase64Padding_ShouldStillWork()
        {
            // If someone passes base64 with padding, it should still decode
            // (though our encoder never produces padding)
            var result = Base64Url.Decode("YWJjZA==");
            var decoded = Encoding.UTF8.GetString(result);
            decoded.Should().Be("abcd");
        }

        [Fact]
        public void Decode_WithPlusAndSlash_ShouldDecode()
        {
            // Standard base64 characters should still work
            // (for backwards compatibility or external input)
            var result = Base64Url.Decode("A+M=");
            result.Should().Equal(new byte[] { 0x03, 0xE3 });
        }

        [Fact]
        public void Encode_ResultNeverContainsPadding()
        {
            // Comprehensive check that no padding is ever produced
            var random = new Random(42);
            for (int length = 0; length < 100; length++)
            {
                var input = new byte[length];
                random.NextBytes(input);

                var encoded = Base64Url.Encode(input);
                encoded.Should().NotContain("=", $"Padding found for length {length}");
            }
        }

        [Fact]
        public void Encode_ResultOnlyContainsValidChars()
        {
            // Valid base64url chars: A-Z, a-z, 0-9, -, _
            var validChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

            var random = new Random(42);
            for (int i = 0; i < 50; i++)
            {
                var input = new byte[random.Next(1, 100)];
                random.NextBytes(input);

                var encoded = Base64Url.Encode(input);
                foreach (var c in encoded)
                {
                    validChars.Should().Contain(c.ToString(),
                        $"Invalid character '{c}' found in encoded output");
                }
            }
        }

        [Fact]
        public void RoundTrip_ConsecutiveOperations_ShouldMatch()
        {
            // Test multiple consecutive encode/decode operations
            var original = Encoding.UTF8.GetBytes("test data");

            var encoded1 = Base64Url.Encode(original);
            var decoded1 = Base64Url.Decode(encoded1);
            decoded1.Should().Equal(original);

            var encoded2 = Base64Url.Encode(decoded1);
            var decoded2 = Base64Url.Decode(encoded2);
            decoded2.Should().Equal(original);

            encoded1.Should().Be(encoded2);
        }

        [Fact]
        public void Decode_CaseSensitive_ShouldBeDifferent()
        {
            // Base64 is case-sensitive
            var upper = Base64Url.Decode("AQID");
            var lower = Base64Url.Decode("aqid");

            upper.Should().NotEqual(lower);
        }

        [Fact]
        public void RoundTrip_TypicalJwsHeader_ShouldMatch()
        {
            // Test with actual JWS header structure
            var header = "{\"alg\":\"ES512\",\"kid\":\"45fc75cf-5649-4134-84b3-192c2c78e990\",\"tl_version\":\"2\",\"tl_headers\":\"Idempotency-Key\"}";
            var original = Encoding.UTF8.GetBytes(header);

            var encoded = Base64Url.Encode(original);
            var decoded = Base64Url.Decode(encoded);

            decoded.Should().Equal(original);
            Encoding.UTF8.GetString(decoded).Should().Be(header);
        }

        [Fact]
        public void RoundTrip_TypicalSignature_ShouldMatch()
        {
            // Test with signature-like data (132 bytes for ES512)
            var signature = new byte[132];
            new Random(42).NextBytes(signature);

            var encoded = Base64Url.Encode(signature);
            var decoded = Base64Url.Decode(encoded);

            decoded.Should().Equal(signature);
            decoded.Length.Should().Be(132);
        }

        #endregion

        #region RFC 4648 Compliance Tests

        [Fact]
        public void Rfc4648_TestVector1_ShouldEncode()
        {
            // RFC 4648 test vectors adapted for base64url
            var input = Encoding.ASCII.GetBytes("");
            var result = Base64Url.Encode(input);
            result.Should().Be("");
        }

        [Fact]
        public void Rfc4648_TestVector2_ShouldEncode()
        {
            var input = Encoding.ASCII.GetBytes("f");
            var result = Base64Url.Encode(input);
            result.Should().Be("Zg"); // No padding
        }

        [Fact]
        public void Rfc4648_TestVector3_ShouldEncode()
        {
            var input = Encoding.ASCII.GetBytes("fo");
            var result = Base64Url.Encode(input);
            result.Should().Be("Zm8"); // No padding
        }

        [Fact]
        public void Rfc4648_TestVector4_ShouldEncode()
        {
            var input = Encoding.ASCII.GetBytes("foo");
            var result = Base64Url.Encode(input);
            result.Should().Be("Zm9v");
        }

        [Fact]
        public void Rfc4648_TestVector5_ShouldEncode()
        {
            var input = Encoding.ASCII.GetBytes("foob");
            var result = Base64Url.Encode(input);
            result.Should().Be("Zm9vYg"); // No padding
        }

        [Fact]
        public void Rfc4648_TestVector6_ShouldEncode()
        {
            var input = Encoding.ASCII.GetBytes("fooba");
            var result = Base64Url.Encode(input);
            result.Should().Be("Zm9vYmE"); // No padding
        }

        [Fact]
        public void Rfc4648_TestVector7_ShouldEncode()
        {
            var input = Encoding.ASCII.GetBytes("foobar");
            var result = Base64Url.Encode(input);
            result.Should().Be("Zm9vYmFy");
        }

        #endregion
    }
}
