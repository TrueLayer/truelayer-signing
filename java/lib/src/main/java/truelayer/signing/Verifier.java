package truelayer.signing;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;

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

    private String path = "";

    private byte[] body = new byte[0];

    private final LinkedHashMap<HeaderName, String> headers = new LinkedHashMap<>();

    private final HashSet<String> requiredHeaders = new HashSet<>();

    private Verifier(ECPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    /**
     * Add the request method.
     */
    public Verifier method(String method) {
        this.method = method;
        return this;
    }

    /**
     * Add the request absolute path starting with a leading `/` and without any trailing slashes.
     */
    public Verifier path(String path) {
        this.path = path;
        return this;
    }

    /**
     * Add the full unmodified request body.
     */
    public Verifier body(byte[] body) {
        this.body = body;
        return this;
    }

    /**
     * Add a header name and value.
     * May be called multiple times to add multiple different headers.
     * Warning: Only a single value per header name is supported.
     */
    public Verifier header(String name, String value) {
        this.headers.put(new HeaderName(name), value);
        return this;
    }

    /**
     * Require a header name that must be included in the `Tl-Signature`.
     * May be called multiple times to add multiple required headers.
     */
    public Verifier requiredHeader(String header) {
        this.requiredHeaders.add(header);
        return this;
    }

    /**
     * Start building a `Tl-Signature` header verifier using public key RFC 7468 PEM-encoded data.
     *
     * @param publicKeyPem the public key 7468 PEM-encoded data
     * @throws InvalidKeyException it the provided key is invalid
     */
    public static Verifier from(byte[] publicKeyPem) {
        ECPublicKey publicKey = InvalidKeyException.evaluate(() -> ECKey.parseFromPEMEncodedObjects(new String(publicKeyPem)).toECKey().toECPublicKey());
        return new Verifier(publicKey);
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
                missingRequiredHeader.isEmpty(),
                "missing required header: " + missingRequiredHeader.orElse("")
        );

        return tl_headers.get().collect(Collectors.toList());
    }
}
