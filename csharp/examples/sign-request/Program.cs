using System;
using System.Net.Http;
using System.Text;
using TrueLayer.Signing;

namespace TrueLayer.ExampleWebhookServer
{
    public class Program
    {
        public static void Main(string[] args)
        {
            // Read required env vars
            var accessToken = Environment.GetEnvironmentVariable("ACCESS_TOKEN")
                ?? throw new Exception("Missing env var ACCESS_TOKEN");
            var kid = Environment.GetEnvironmentVariable("KID")
                ?? throw new Exception("Missing env var KID");
            var privateKeyPem = Environment.GetEnvironmentVariable("PRIVATE_KEY")
                ?? throw new Exception("Missing env var PRIVATE_KEY");

            // A random body string is enough for this request as `/test-signature` endpoint does not 
            // require any schema, it simply checks the signature is valid against what's received.
            var body = $"msg-{new Random().Next()}";
            var idempotencyKey = Guid.NewGuid().ToString();

            var tlSignature = Signer.SignWithPem(kid, privateKeyPem)
                .Method("POST") // as we're sending a POST request
                .Path("/test-signature") // the path of our request
                // Optional: /test-signature does not require any headers, but we may sign some anyway.
                // All signed headers *must* be included unmodified in the request.
                .Header("Idempotency-Key", idempotencyKey)
                .Body(body) // body of our request
                .Sign();

            var request = new HttpRequestMessage(HttpMethod.Post, "https://api.truelayer-sandbox.com/test-signature");
            // Request body & any signed headers *must* exactly match what was used to generate the signature.
            request.Content = new StringContent(body, Encoding.UTF8);
            request.Headers.Add("Idempotency-Key", idempotencyKey);
            request.Headers.Add("Authorization", $"Bearer {accessToken}");
            request.Headers.Add("Tl-Signature", tlSignature);

            Console.WriteLine($"Sending {request}\nbody: {body}\n");

            var response = new HttpClient().Send(request);
            var responseBody = response.IsSuccessStatusCode ? "✓" : response.Content.ReadAsStringAsync().Result;
            // 204 means success
            // 401 means either the access token is invalid, or the signature is invalid.
            Console.WriteLine($"{(int)response.StatusCode} {responseBody}");
        }
    }
}
