package truelayer.signing;

import com.nimbusds.jose.util.Base64URL;

import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.Map;
import java.util.stream.Collectors;

public class Utils {
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
