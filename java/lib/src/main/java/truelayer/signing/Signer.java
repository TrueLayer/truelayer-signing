package truelayer.signing;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;

import java.security.interfaces.ECPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;

import static truelayer.signing.Utils.jwsHeaderMap;

/**
 * Builder to generate a Tl-Signature header value using a private key.
 */
final public class Signer {

    private final String kid;
    private final ECPrivateKey ecPrivateKey;

    private String path = "";
    private String method = "";
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
     */
    public Signer path(String path) {
        if (path == null)
            throw new IllegalArgumentException("the path must not be null");
        this.path = path;
        return this;
    }

    /**
     * Add the full request body. Note: This *must* be identical to what is sent with the request.
     *
     * @param body - the full request body must not be null
     * @return the Signer instance
     */
    public Signer body(byte[] body) {
        if (body == null)
            throw new IllegalArgumentException("the body must not be null");

        this.body = body;
        return this;
    }

    /**
     * Add a header name and value. May be called multiple times to add multiple different headers.
     * Warning: Only a single value per header name is supported.
     *
     * @param name  - must not be null
     * @param value - must not be null
     * @return the Signer instance
     */
    public Signer header(String name, String value) {
        if (name == null || value == null)
            throw new IllegalArgumentException("header name and value must not be null");
        this.headers.put(new HeaderName(name), value);
        return this;
    }


    /**
     * Start building a request Tl-Signature header value using private key
     * RFC 7468 PEM-encoded data and the key's kid.
     *
     * @param kid           key identifier of the private key - must not be null
     * @param privateKeyPem the privateKey RFC 7468 PEM-encoded - must not be null
     * @return the Signer instance
     * @throws InvalidKeyException if the provided key is invalid
     */
    public static Signer from(String kid, byte[] privateKeyPem) {
        ECPrivateKey privateKey = InvalidKeyException.evaluate(() ->
                ECKey.parseFromPEMEncodedObjects(new String(privateKeyPem)).toECKey().toECPrivateKey());

        return new Signer(kid, privateKey);
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
