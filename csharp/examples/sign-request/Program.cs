using System;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Net.Mime;
using System.Text;
using System.Text.Json;
using System.Threading.Tasks;
using TrueLayer.Signing;

namespace TrueLayer.ExampleSignRequest
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            // Read required env vars
            var accessToken = Environment.GetEnvironmentVariable("ACCESS_TOKEN")
                ?? throw new Exception("Missing env var ACCESS_TOKEN");
            var kid = Environment.GetEnvironmentVariable("KID")
                ?? throw new Exception("Missing env var KID");
            var privateKeyPem = Environment.GetEnvironmentVariable("PRIVATE_KEY")
                ?? throw new Exception("Missing env var PRIVATE_KEY");

            // A random body is enough for this request as `/test-signature` endpoint does not
            // require any schema, it simply checks the signature is valid against what's received.
            var body = new
            {
                currency = "GBP",
                max_amount_in_minor = 10000,
                name = "Test Payment",
                remitter = new
                {
                    account_holder_name = "John Doe",
                    account_identifier = new
                    {
                        type = "sort_code_account_number",
                        sort_code = "123456",
                        account_number = "12345678"
                    }
                },
                beneficiary = new
                {
                    type = "merchant_account",
                    merchant_account_id = "a61acaef-ee05-4077-92f3-25543a11bd8d",
                    account_holder_name = "Merchant Ltd"
                },
                metadata = new
                {
                    order_id = $"order-{new Random().Next()}"
                }
            };

            // Serialize to byte[] to ensure exact same bytes are used for signing and sending
            var jsonOptions = new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase };
            var bodyBytes = JsonSerializer.SerializeToUtf8Bytes(body, jsonOptions);
            var idempotencyKey = Guid.NewGuid().ToString();

            var tlSignature = Signer.SignWithPem(kid, privateKeyPem)
                .Method("POST") // as we're sending a POST request
                .Path("/test-signature") // the path of our request
                // Optional: /test-signature does not require any headers, but we may sign some anyway.
                // All signed headers *must* be included unmodified in the request.
                .Header("Idempotency-Key", idempotencyKey)
                .Body(bodyBytes) // body of our request as byte[]
                .Sign();

            var request = new HttpRequestMessage(HttpMethod.Post, "https://api.truelayer-sandbox.com/test-signature");
            // Request body & any signed headers *must* exactly match what was used to generate the signature.
            request.Content = new ByteArrayContent(bodyBytes)
            {
                Headers = { ContentType = new MediaTypeHeaderValue(MediaTypeNames.Application.Json) }
            };
            request.Headers.Add("Idempotency-Key", idempotencyKey);
            request.Headers.Add("Authorization", $"Bearer {accessToken}");
            request.Headers.Add("Tl-Signature", tlSignature);

            Console.WriteLine($"Sending {request}\nbody: {Encoding.UTF8.GetString(bodyBytes)}\n");

            using var httpClient = new HttpClient();
            using var response = await httpClient.SendAsync(request);
            var responseBody = response.IsSuccessStatusCode ? "✓" : await response.Content.ReadAsStringAsync();
            // 204 means success
            // 401 means either the access token is invalid, or the signature is invalid.
            Console.WriteLine($"{(int)response.StatusCode} {responseBody}");
        }
    }
}
