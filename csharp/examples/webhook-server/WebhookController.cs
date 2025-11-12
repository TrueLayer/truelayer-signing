using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using TrueLayer.Signing;

namespace TrueLayer.ExampleWebhookServer;

[ApiController]
[Route("[controller]")]
public sealed class WebhookController(IHttpClientFactory httpClientFactory) : ControllerBase
{
    private static readonly HashSet<string> AllowedJkus =
    [
        "https://webhooks.truelayer.com/.well-known/jwks",
        "https://webhooks.truelayer-sandbox.com/.well-known/jwks"
    ];

    // Note: Webhook path can be whatever is configured, here a unique path
    // is used matching the README example signature.
    [HttpPost("/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b")]
    [ProducesResponseType(StatusCodes.Status202Accepted)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> PostHook(
        HttpRequest request,
        [FromHeader(Name = "Tl-Signature")] string? tlSignature)
    {
        if (string.IsNullOrEmpty(tlSignature))
        {
            return Unauthorized(new { error = "Missing Tl-Signature header" });
        }

        await VerifyRequest(request, tlSignature);

        // handle verified webhook
        return Accepted();
    }

    async Task VerifyRequest(HttpRequest request, string tlSignature)
    {
        // Extract jku from signature
        var jku = Verifier.ExtractJku(tlSignature);

        // Ensure jku is an expected TrueLayer url
        if (!AllowedJkus.Contains(jku))
        {
            throw new InvalidOperationException($"Unpermitted jku: {jku}");
        }

        // Fetch jwks (should cache this according to headers)
        using var httpClient = httpClientFactory.CreateClient("JwksClient");
        var jwks = await httpClient.GetByteArrayAsync(jku);

        // Read request body as bytes to avoid encoding issues
        using var ms = new System.IO.MemoryStream();
        await request.Body.CopyToAsync(ms);

        // Verify request using StringValues overload for direct IHeaderDictionary compatibility
        Verifier.VerifyWithJwks(jwks)
            .Method("POST")
            .Path(request.Path)
            .Headers(request.Headers)
            .Body(ms.ToArray())
            .Verify(tlSignature);
    }
}
