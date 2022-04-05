package com.truelayer.signing.examples.webhook_server;

import com.truelayer.signing.SignatureException;
import io.javalin.Javalin;
import okhttp3.Cache;
import okhttp3.OkHttpClient;

import java.nio.file.Paths;

public class WebhookServer {

    public static void main(String[] args) {
        int cacheSize = 10 * 1024 * 1024; // 10 MiB
        Cache cache = new Cache(Paths.get("", ".cache").toFile(), cacheSize);

        OkHttpClient httpClient = new OkHttpClient.Builder().cache(cache).build();

        Javalin app = Javalin.create().exception(SignatureException.class, (exception, ctx) -> {
            System.out.println("WARNING: Verification failed " + exception.getMessage());
            ctx.status(401);
        }).start(7000);

        app.post("/hook/d7a2c49d-110a-4ed2-a07d-8fdb3ea6424b", new WebhookVerificationHandler(httpClient));
    }
}
