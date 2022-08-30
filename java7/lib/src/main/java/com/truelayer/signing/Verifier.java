package com.truelayer.signing;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWKSet;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.*;

/**
 * Builder to verify a request against a `Tl-Signature` header using a public key.
 */
public abstract class Verifier {

    protected String method = "";

    protected String path = "";

    protected byte[] body = new byte[0];

    protected final LinkedHashMap<HeaderName, String> headers = new LinkedHashMap<>();

    protected final HashSet<String> requiredHeaders = new HashSet<>();


    /**
     * Extract jku (JSON Web Key URL) from unverified jws Tl-Signature.
     * Used in webhook signatures providing the public key jwk url.
     *
     * @param tlSignature unverified jws Tl-Signature
     * @return jku (JSON Web Key URL)
     * @throws ParseException if the signature is invalid
     */
    public static String extractJku(String tlSignature) throws SignatureException {
        URI uri;
        try {
            uri = JWSObject.parse(tlSignature).getHeader().getJWKURL();
        } catch (ParseException e) {
            throw new SignatureException(e);
        }
        return uri.toString();
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
     * @throws IllegalArgumentException if the provided param is null or invalid
     */
    public Verifier path(String path) {
        if (path == null)
            throw new IllegalArgumentException("the path must not be null");
        if (!path.startsWith("/"))
            throw new IllegalArgumentException("invalid path " + path + " must start with '/'");
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
     * Add a Map of headers.
     * Warning: Only a single value per header name is supported.
     *
     * @param headers - must not be null
     * @return the Verifier instance
     * @throws IllegalArgumentException if the provided params are null
     */
    public Verifier headers(Map<String, String> headers) {
        if (headers == null)
            throw new IllegalArgumentException("headers must not be null");
        for (Map.Entry<String, String> entry : headers.entrySet()) {
            this.headers.put(new HeaderName(entry.getKey()), entry.getValue());
        }
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
    public static Verifier from(byte[] publicKeyPem) throws KeyException {
        if (publicKeyPem == null)
            throw new IllegalArgumentException("the publicKey must not be null");

        ECPublicKey publicKey;
        try {
            publicKey = ECKey.parseFromPEMEncodedObjects(new String(publicKeyPem)).toECKey().toECPublicKey();
        } catch (JOSEException e) {
            throw new KeyException(e);
        }

        return new VerifierFromPublicKey(publicKey);
    }

    /**
     * Start building a `Tl-Signature` header verifier using public key RFC 7468 PEM-encoded data.
     *
     * @param publicKeyPem the public key 7468 PEM-encoded data - must not be null
     * @return the Verifier instance
     * @throws KeyException             it the provided key is invalid
     * @throws IllegalArgumentException if the provided param is null
     */
    public static Verifier from(String publicKeyPem) throws KeyException {
        if (publicKeyPem == null)
            throw new IllegalArgumentException("the publicKey must not be null");

        ECPublicKey publicKey;
        try {
            publicKey = ECKey.parseFromPEMEncodedObjects(publicKeyPem).toECKey().toECPublicKey();
        } catch (JOSEException e) {
            throw new KeyException(e);
        }
        return new VerifierFromPublicKey(publicKey);
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

        return new VerifierFromPublicKey(publicKeyPem);
    }

    /**
     * Start building a `Tl-Signature` header verifier using public key JWKs JSON response data.
     *
     * @param jwks public key JWKs JSON response data
     * @return the Verifier instance
     * @throws SignatureException if the provided jwks is invalid
     */
    public static Verifier verifyWithJwks(String jwks) throws ParseException {
        JWKSet jwkSet = JWKSet.parse(jwks);
        return new VerifierFromJwks(jwkSet);
    }

    /**
     * Verify the given `Tl-Signature` header value.
     *
     * @param signature the given `TL-signature`
     * @throws SignatureException if Signature is invalid
     */
    public abstract void verify(String signature);

    protected Map<HeaderName, String> validateSignatureHeader(JWSHeader jwsHeader) {

        List<String> validSignatureHeaders = validateSignatureHeaders(jwsHeader, requiredHeaders);

        LinkedHashMap<HeaderName, String> orderedHeaders = new LinkedHashMap<>();

        for (String header : validSignatureHeaders) {
            String val = headers.get(new HeaderName(header));
            if (val != null)
                orderedHeaders.put(new HeaderName(header), val);
        }

        return orderedHeaders;
    }

    private List<String> validateSignatureHeaders(JWSHeader jwsHeader, HashSet<String> requiredHeaders) throws SignatureException {
        SignatureException.ensure(jwsHeader.getAlgorithm().equals(JWSAlgorithm.ES512), "unsupported jws alg");
        SignatureException.ensure(jwsHeader.getCustomParam("tl_version").toString().equals("2"), "unsupported jws tl_version");

        List<String> signedHeaders = Arrays.asList(jwsHeader.getCustomParam("tl_headers").toString().split(","));

        List<String> missingHeaders = new ArrayList<>();
        for (String h : requiredHeaders) {
            boolean found = false;
            for (String sh : signedHeaders) {
                if (sh.equals(h)) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                missingHeaders.add(h);
            }
        }

        if (missingHeaders.size() > 0) {
            throw new SignatureException("missing required header: " + missingHeaders.get(0));
        }

        return signedHeaders;
    }
}
