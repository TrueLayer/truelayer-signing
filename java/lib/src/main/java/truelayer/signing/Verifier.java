package truelayer.signing;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.util.*;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * Builder to verify a request against a `Tl-Signature` header using a public key.
 */
final public class Verifier {

    private final ECPublicKey publicKey;

    private String method = "";

    private String path = "POST";

    private byte[] body = new byte[0];

    private final LinkedHashMap<HeaderName, String> headers = new LinkedHashMap<>();

    private final HashSet<String> requiredHeaders = new HashSet<>();

    private Verifier(ECPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Add the request method.
     *
     * @param method - the request method must be non null
     * @return the Verifier instance
     * @throws IllegalArgumentException if the provided param is null
     */
    public Verifier method(String method) {
        if (method == null)
            throw new IllegalArgumentException("the method must not be null");

        this.method = method;
        return this;
    }

    /**
     * Add the request absolute path starting with a leading `/` and without any trailing slashes.
     *
     * @param path - the request absolute path must not be null
     * @return the Verifier instance
     * @throws IllegalArgumentException if the provided param is null
     */
    public Verifier path(String path) {
        if (path == null)
            throw new IllegalArgumentException("the path must not be null");
        this.path = path;
        return this;
    }

    /**
     * Add the full unmodified request body.
     *
     * @param body - the full request body must not be null
     * @return the Verifier instance
     * @throws IllegalArgumentException if the provided param is null
     */
    public Verifier body(byte[] body) {
        if (body == null)
            throw new IllegalArgumentException("the body must not be null");

        this.body = body;
        return this;
    }

    /**
     * Add the full unmodified request body.
     *
     * @param body - the full request body must not be null
     * @return the Verifier instance
     * @throws IllegalArgumentException if the provided param is null
     */
    public Verifier body(String body) {
        if (body == null)
            throw new IllegalArgumentException("the body must not be null");

        this.body = body.getBytes(StandardCharsets.UTF_8);
        return this;
    }

    /**
     * Add a header name and value.
     * May be called multiple times to add multiple different headers.
     * Warning: Only a single value per header name is supported.
     *
     * @param name  - must not be null
     * @param value - must not be null
     * @return the Verifier instance
     * @throws IllegalArgumentException if the provided param is null
     */
    public Verifier header(String name, String value) {
        if (name == null || value == null)
            throw new IllegalArgumentException("header name and value must not be null");
        this.headers.put(new HeaderName(name), value);
        return this;
    }

    /**
     * Require a header name that must be included in the `Tl-Signature`.
     * May be called multiple times to add multiple required headers.
     *
     * @param name - must not be null
     * @return the Verifier instance
     * @throws IllegalArgumentException if the provided param is null
     */
    public Verifier requiredHeader(String name) {
        if (name == null)
            throw new IllegalArgumentException("the required header name must not be null");
        this.requiredHeaders.add(name);
        return this;
    }

    /**
     * Start building a `Tl-Signature` header verifier using public key RFC 7468 PEM-encoded data.
     *
     * @param publicKeyPem the public key 7468 PEM-encoded data - must not be null
     * @return the Verifier instance
     * @throws KeyException             it the provided key is invalid
     * @throws IllegalArgumentException if the provided param is null
     */
    public static Verifier from(byte[] publicKeyPem) {
        if (publicKeyPem == null)
            throw new IllegalArgumentException("the publicKey must not be null");

        ECPublicKey publicKey = KeyException.evaluate(() -> ECKey.parseFromPEMEncodedObjects(new String(publicKeyPem)).toECKey().toECPublicKey());
        return new Verifier(publicKey);
    }

    /**
     * Start building a `Tl-Signature` header verifier using public key RFC 7468 PEM-encoded data.
     *
     * @param publicKeyPem the public key 7468 PEM-encoded data - must not be null
     * @return the Verifier instance
     * @throws KeyException             it the provided key is invalid
     * @throws IllegalArgumentException if the provided param is null
     */
    public static Verifier from(String publicKeyPem) {
        if (publicKeyPem == null)
            throw new IllegalArgumentException("the publicKey must not be null");

        ECPublicKey publicKey = KeyException.evaluate(() -> ECKey.parseFromPEMEncodedObjects(publicKeyPem).toECKey().toECPublicKey());
        return new Verifier(publicKey);
    }

    /**
     * Start building a `Tl-Signature` header verifier using public key RFC 7468 PEM-encoded data.
     *
     * @param publicKeyPem the public key 7468 PEM-encoded data - must not be null
     * @return the Verifier instance
     * @throws KeyException             it the provided key is invalid
     * @throws IllegalArgumentException if the provided param is null
     */
    public static Verifier from(ECPublicKey publicKeyPem) {
        if (publicKeyPem == null)
            throw new IllegalArgumentException("the publicKey must not be null");

        return new Verifier(publicKeyPem);
    }

    /**
     * Verify the given `Tl-Signature` header value.
     *
     * @param signature the given `TL-signature`
     * @throws SignatureException if Signature is invalid
     */
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
                !missingRequiredHeader.isPresent(),
                "missing required header: " + missingRequiredHeader.orElse("")
        );

        return tl_headers.get().collect(Collectors.toList());
    }
}
