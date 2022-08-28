package com.truelayer.signing.examples.webhook_server;

import com.truelayer.signing.Verifier;
import io.javalin.http.BadRequestResponse;
import io.javalin.http.Context;
import io.javalin.http.Handler;
import io.javalin.http.InternalServerErrorResponse;
import okhttp3.OkHttpClient;
import okhttp3.Request;
import okhttp3.Response;
import okhttp3.ResponseBody;
import org.jetbrains.annotations.NotNull;

import java.util.Map;

public class WebhookVerificationHandler implements Handler {

    private final OkHttpClient httpClient;

    public WebhookVerificationHandler(OkHttpClient httpClient) {
        this.httpClient = httpClient;
    }

    @Override
    public void handle(@NotNull Context ctx) throws Exception {
        // extract jku from signature
        String tlSignature = ctx.header("Tl-Signature");
        if (tlSignature == null) throw new BadRequestResponse("Missing Tl-Signature header");

        String jku = Verifier.extractJku(tlSignature);

        // ensure jku is an expected TrueLayer url
        if (!jku.equals("https://webhooks.truelayer.com/.well-known/jwks")
                && !jku.equals("https://webhooks.truelayer-sandbox.com/.well-known/jwks")) {
            throw new BadRequestResponse("Unpermitted jku " + jku);
        }

        // fetch jwks (should cache this according to headers)
        // http GET request to jku url
        try (Response response = httpClient.newCall(new Request.Builder().url(jku).build()).execute()) {
            if (response.code() == 200) {
                ResponseBody body = response.body();
                if (body == null) throw new InternalServerErrorResponse();
                String jwks = body.string();

                Map<String, String> requestHeaders = ctx.headerMap();
                byte[] requestBody = ctx.bodyAsBytes();

                // verify request
                Verifier.verifyWithJwks(jwks)
                        .body(requestBody)
                        .headers(requestHeaders)
                        .path(ctx.path())
                        .method("POST")
                        .verify(tlSignature);

                ctx.status(202);
            } else
                ctx.status(401);
        }
    }
}
