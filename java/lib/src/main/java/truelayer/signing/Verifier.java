package truelayer.signing;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;

import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

final public class Verifier {

    private final ECPublicKey publicKey;

    private String method = "";

    private String path = "";

    private byte[] body = new byte[0];

    private final LinkedHashMap<HeaderName, String> headers = new LinkedHashMap<>();

    private final HashSet<String> requiredHeaders = new HashSet<>();

    private Verifier(ECPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    public Verifier method(String method) {
        this.method = method;
        return this;
    }

    public Verifier path(String path) {
        this.path = path;
        return this;
    }

    public Verifier body(byte[] body) {
        this.body = body;
        return this;
    }

    public Verifier header(String name, String value) {
        this.headers.put(new HeaderName(name), value);
        return this;
    }

    public Verifier requiredHeader(String header) {
        this.requiredHeaders.add(header);
        return this;
    }

    public static Verifier from(byte[] publicKeyPem) {
        ECPublicKey publicKey = InvalidKeyException.evaluate(() -> ECKey.parseFromPEMEncodedObjects(new String(publicKeyPem)).toECKey().toECPublicKey());
        return new Verifier(publicKey);
    }

    public void verify(String signature) {
        JWSHeader jwsHeader = SignatureException.evaluate(() -> JWSHeader.parse(JOSEObject.split(signature)[0]));
        List<String> validSignatureHeaders = validateSignatureHeaders(jwsHeader, requiredHeaders);

        LinkedHashMap<HeaderName, String> orderedHeaders = new LinkedHashMap<>();
        validSignatureHeaders.forEach(h -> {
            String value = headers.get(new HeaderName(h));
            if (value != null)
                orderedHeaders.put(new HeaderName(h), value);
        });

        Boolean verifiedResult = SignatureException.evaluate(() ->
                JWSObject.parse(signature, new Payload(Utils.buildPayload(orderedHeaders, method, path, body)))
                        .verify(new ECDSAVerifier(publicKey)));

        SignatureException.ensure(verifiedResult, "invalid signature");
    }

    private List<String> validateSignatureHeaders(JWSHeader jwsHeader, HashSet<String> requiredHeaders) {
        SignatureException.ensure(jwsHeader.getAlgorithm().equals(JWSAlgorithm.ES512), "unsupported jws alg");
        SignatureException.ensure(jwsHeader.getCustomParam("tl_version").toString().equals("2"), "unsupported jws tl_version");

        Supplier<Stream<String>> tl_headers =
                () -> Arrays.stream(jwsHeader.getCustomParam("tl_headers").toString().split(",")).map(String::trim);

        Optional<String> missingRequiredHeader = requiredHeaders.stream()
                .filter(rHeader -> tl_headers.get().noneMatch(tlHeader -> tlHeader.toLowerCase().contains(rHeader.toLowerCase())))
                .findAny();

        SignatureException.ensure(
                missingRequiredHeader.isEmpty(),
                "missing required header: " + missingRequiredHeader.orElse("")
        );

        return tl_headers.get().collect(Collectors.toList());
    }
}
