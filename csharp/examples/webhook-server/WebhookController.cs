using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Mvc;
using TrueLayer.Signing;

namespace TrueLayer.ExampleWebhookServer
{
    [ApiController]
    public sealed class WebhookController : ControllerBase
    {
        private readonly HttpClient _http;

        public WebhookController(HttpClient httpClient) => _http = httpClient;

        // Note: Webhook path can be whatever is configured, here a unique path 
        // is used matching the README example signature.
        [HttpPost("/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b")]
        public async Task<StatusCodeResult> PostHook()
        {
            try
            {
                await VerifyRequest();
            }
            catch (Exception ex)
            {
                Console.WriteLine($"WARNING: Verification failed: {ex.Message ?? ex.GetType().Name}");
                return StatusCode(401);
            }

            // handle verified webhook
            return StatusCode(202);
        }

        async Task VerifyRequest()
        {
            // extract jku from signature
            HttpContext.Request.Headers.TryGetValue("Tl-Signature", out var tlSignature);
            if (!tlSignature.Any()) throw new InvalidOperationException("Missing Tl-Signature header");

            var jku = Verifier.ExtractJku(tlSignature);

            // ensure jku is an expected TrueLayer url
            if (jku != "https://webhooks.truelayer.com/.well-known/jwks"
                && jku != "https://webhooks.truelayer-sandbox.com/.well-known/jwks")
            {
                throw new InvalidOperationException($"unpermitted jku `{jku}`");
            }

            // fetch jwks (should cache this according to headers)
            var jwksResponse = await _http.GetAsync(jku);
            jwksResponse.EnsureSuccessStatusCode();
            var jwks = await jwksResponse.Content.ReadAsByteArrayAsync();

            // verify request
            var allHeaders = HttpContext.Request.Headers.Select(h => KeyValuePair.Create(h.Key, h.Value.First()));
            var body = await new System.IO.StreamReader(HttpContext.Request.Body).ReadToEndAsync();

            Verifier.VerifyWithJwks(jwks)
                .Method("POST")
                .Path(HttpContext.Request.Path)
                .Headers(allHeaders)
                .Body(body)
                .Verify(tlSignature);
        }
    }
}
