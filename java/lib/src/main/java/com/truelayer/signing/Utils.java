package com.truelayer.signing;

import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Collectors;

public class Utils {

    protected static Map<String, Object> jwsHeaderMap(String kid, Map<HeaderName, String> headers) {
        Map<String, Object> jwsheader = new HashMap<>();
        jwsheader.put("alg", "ES512");
        jwsheader.put("kid", kid);
        jwsheader.put("tl_version", "2");
        jwsheader.put("tl_headers", headers.keySet().stream().map(HeaderName::getName).collect(Collectors.joining(",")));
        return jwsheader;
    }

    public static Base64URL buildPayload(Map<HeaderName, String> headers, String method, String path, byte[] body) {

        String headersString = headers.keySet().stream().map(k -> k.getName() + ": " + headers.get(k)).collect(Collectors.joining("\n"));

        String payload = new StringBuilder(method.toUpperCase())
                .append(" ")
                .append(path)
                .append("\n")
                .append(headersString)
                .append("\n")
                .append(new String(body))
                .toString();

        return Base64URL.from(Base64.getEncoder().withoutPadding().encodeToString(payload.getBytes(StandardCharsets.UTF_8)));
    }
}
