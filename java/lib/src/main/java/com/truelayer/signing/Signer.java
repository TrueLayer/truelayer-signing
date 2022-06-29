package com.truelayer.signing;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;

import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;

import static com.truelayer.signing.Utils.jwsHeaderMap;

/**
 * Builder to generate a Tl-Signature header value using a private key.
 */
final public class Signer {

    private final String kid;
    private final ECPrivateKey ecPrivateKey;

    private String path = "";
    private String method = "POST";
    private byte[] body = new byte[0];
    private final Map<HeaderName, String> headers = new LinkedHashMap<>();

    private Signer(String kid, ECPrivateKey ecPrivateKey) {
        this.kid = kid;
        this.ecPrivateKey = ecPrivateKey;
    }

    /**
     * Add the request method, defaults to `"POST"` if unspecified.
     *
     * @param method - the request method must be non null
     * @return the Signer instance
     * @throws IllegalArgumentException if the provided param is null
     */
    public Signer method(String method) {
        if (method == null)
            throw new IllegalArgumentException("the method must not be null");
        this.method = method;
        return this;
    }

    /**
     * Add the request absolute path starting with a leading `/` and without any trailing slashes.
     *
     * @param path - the request absolute path must not be null
     * @return the Signer instance
     * @throws IllegalArgumentException if the provided param is null or invalid
     */
    public Signer path(String path) {
        if (path == null)
            throw new IllegalArgumentException("the path must not be null");
        if(!path.startsWith("/"))
            throw new IllegalArgumentException("invalid path " + path + " must start with '/'");
        this.path = path;
        return this;
    }

    /**
     * Add the full request body. Note: This *must* be identical to what is sent with the request.
     *
     * @param body - the full request body must not be null
     * @return the Signer instance
     * @throws IllegalArgumentException if the provided param is null
     */
    public Signer body(byte[] body) {
        if (body == null)
            throw new IllegalArgumentException("the body must not be null");

        this.body = body;
        return this;
    }

    /**
     * Add the full request body. Note: This *must* be identical to what is sent with the request.
     *
     * @param body - the full request body must not be null
     * @return the Signer instance
     * @throws IllegalArgumentException if the provided param is null
     */
    public Signer body(String body) {
        if (body == null)
            throw new IllegalArgumentException("the body must not be null");

        this.body = body.getBytes(StandardCharsets.UTF_8);
        return this;
    }

    /**
     * Add a header name and value. May be called multiple times to add multiple different headers.
     * Warning: Only a single value per header name is supported.
     *
     * @param name  - must not be null
     * @param value - must not be null
     * @return the Signer instance
     * @throws IllegalArgumentException if the provided params are null
     */
    public Signer header(String name, String value) {
        if (name == null || value == null)
            throw new IllegalArgumentException("header name and value must not be null");
        this.headers.put(new HeaderName(name), value);
        return this;
    }

    /**
     * Add a Map of headers.
     * Warning: Only a single value per header name is supported.
     *
     * @param headers  - must not be null
     * @return the Signer instance
     * @throws IllegalArgumentException if the provided params are null
     */
    public Signer headers(Map<String, String> headers) {
        if (headers == null)
            throw new IllegalArgumentException("headers must not be null");
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            this.headers.put(new HeaderName(entry.getKey()), entry.getValue());
        }
        return this;
    }

    /**
     * Start building a request Tl-Signature header value using private key
     * RFC 7468 PEM-encoded data and the key's kid.
     *
     * @param kid           key identifier of the private key - must not be null
     * @param privateKeyPem the privateKey RFC 7468 PEM-encoded - must not be null
     * @return the Signer instance
     * @throws KeyException             if the provided key is invalid
     * @throws IllegalArgumentException if the provided params are null
     */
    public static Signer from(String kid, byte[] privateKeyPem) {
        if (kid == null || privateKeyPem == null)
            throw new IllegalArgumentException("kid and privateKey must not be null");

        ECPrivateKey privateKey = KeyException.evaluate(() ->
                ECKey.parseFromPEMEncodedObjects(new String(privateKeyPem)).toECKey().toECPrivateKey());

        return new Signer(kid, privateKey);
    }

    /**
     * Start building a request Tl-Signature header value using private key
     * RFC 7468 PEM-encoded data and the key's kid.
     *
     * @param kid           key identifier of the private key - must not be null
     * @param privateKeyPem the privateKey RFC 7468 PEM-encoded - must not be null
     * @return the Signer instance
     * @throws KeyException             if the provided key is invalid
     * @throws IllegalArgumentException if the provided params are null
     */
    public static Signer from(String kid, String privateKeyPem) {
        if (kid == null || privateKeyPem == null)
            throw new IllegalArgumentException("kid and privateKey must not be null");

        ECPrivateKey privateKey = KeyException.evaluate(() ->
                ECKey.parseFromPEMEncodedObjects(privateKeyPem).toECKey().toECPrivateKey());

        return new Signer(kid, privateKey);
    }

    /**
     * Start building a request Tl-Signature header value using private key
     * RFC 7468 PEM-encoded data and the key's kid.
     *
     * @param kid           key identifier of the private key - must not be null
     * @param privateKeyPem the privateKey RFC 7468 PEM-encoded - must not be null
     * @return the Signer instance
     * @throws KeyException             if the provided key is invalid
     * @throws IllegalArgumentException if the provided params are null
     */
    public static Signer from(String kid, ECPrivateKey privateKeyPem) {
        if (kid == null || privateKeyPem == null)
            throw new IllegalArgumentException("kid and privateKey must not be null");

        return new Signer(kid, privateKeyPem);
    }

    /**
     * Produce a JWS `Tl-Signature` v2 header value
     *
     * @return a JWS `Tl-Signature` v2 header value
     * @throws SignatureException if signature fails
     */
    public String sign() {
        return SignatureException.evaluate(() -> {
                    JWSHeader jwsHeader = JWSHeader.parse(jwsHeaderMap(this.kid, this.headers));

                    JWSObject jwsObject = new JWSObject(
                            jwsHeader,
                            new Payload(Utils.buildPayload(headers, method, path, body))
                    );

                    jwsObject.sign(new ECDSASigner(this.ecPrivateKey));

                    return jwsObject.serialize(true);
                }
        );
    }
}
