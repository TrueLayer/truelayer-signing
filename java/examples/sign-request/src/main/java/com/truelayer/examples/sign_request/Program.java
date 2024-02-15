package com.truelayer.examples.sign_request;

import com.truelayer.signing.Signer;
import okhttp3.*;

import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Random;
import java.util.UUID;

public class Program {

    public static void main(String[] args) {
        // Read required env vars
        String access_token = System.getenv("ACCESS_TOKEN");
        if (access_token == null) throw new RuntimeException("Missing env var ACCESS_TOKEN");

        String kid = System.getenv("KID");
        if (kid == null) throw new RuntimeException("Missing env var KID");

        String privateKeyPem = System.getenv("PRIVATE_KEY");
        if (privateKeyPem == null) throw new RuntimeException("Missing env var PRIVATE_KEY");

        // A random body string is enough for this request as `/test-signature` endpoint does not
        // require any schema, it simply checks the signature is valid against what's received.
        String body = "msg-" + Math.random();

        String idempotencyKey = UUID.randomUUID().toString();

        String tlSignature = Signer.from(kid, privateKeyPem)
                .method("POST")
                .path("/test-signature")
                // Optional: /test-signature does not require any headers, but we may sign some anyway.
                // All signed headers *must* be included unmodified in the request.
                .header("Idempotency-Key", idempotencyKey)
                .body(body)
                .sign();

        OkHttpClient httpClient = new OkHttpClient();

        // Request body & any signed headers *must* exactly match what was used to generate the signature.
        Request request = new Request.Builder()
                .url("https://api.truelayer-sandbox.com/test-signature")
                .header("Idempotency-Key", idempotencyKey)
                .header("Authorization", "Bearer " + access_token)
                .header("Tl-Signature", tlSignature)
                .post(RequestBody.create(body.getBytes(StandardCharsets.UTF_8)))
                .build();

        try (Response response = httpClient.newCall(request).execute()) {
            ResponseBody responseBody = response.body();
            // 204 means success
            // 401 means either the access token is invalid, or the signature is invalid.
            System.out.println("" + response.code() + " " + responseBody.string());
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}
