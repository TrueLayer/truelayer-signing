package com.truelayer.signing;

import com.nimbusds.jose.util.Base64URL;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;

import static org.apache.commons.codec.binary.Base64.encodeBase64URLSafeString;

public class Utils {

    protected static Map<String, Object> jwsHeaderMap(String kid, Map<HeaderName, String> headers) {
        StringBuilder sb = new StringBuilder();
        int counter = 0;
        for (Map.Entry<HeaderName, String> entry : headers.entrySet()) {
            HeaderName name = entry.getKey();
            sb.append(name.getName());
            if (counter < headers.size() - 1)
                sb.append(",");
            counter++;
        }

        Map<String, Object> jwsheader = new HashMap<>();
        jwsheader.put("alg", "ES512");
        jwsheader.put("kid", kid);
        jwsheader.put("tl_version", "2");
        jwsheader.put("tl_headers", sb.toString());
        return jwsheader;
    }

    public static Base64URL buildPayload(Map<HeaderName, String> headers, String method, String path, byte[] body) {

        StringBuilder headerStringBuilder = new StringBuilder();
        for (Map.Entry<HeaderName, String> entry : headers.entrySet()) {
            HeaderName name = entry.getKey();
            String val = entry.getValue();
            headerStringBuilder.append(name.getName());
            headerStringBuilder.append(": ");
            headerStringBuilder.append(val);
            headerStringBuilder.append("\n");
        }

        String payload = method.toUpperCase() +
                " " +
                path +
                "\n" +
                headerStringBuilder +
                new String(body);


        String base64payload = encodeBase64URLSafeString(payload.getBytes(StandardCharsets.UTF_8));
        return Base64URL.from(base64payload);
    }
}
