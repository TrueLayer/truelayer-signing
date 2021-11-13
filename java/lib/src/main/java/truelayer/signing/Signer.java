package truelayer.signing;

import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSASigner;
import com.nimbusds.jose.jwk.ECKey;

import java.security.interfaces.ECPrivateKey;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.stream.Collectors;

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

    public Signer method(String method) {
        this.method = method;
        return this;
    }

    public Signer path(String path) {
        this.path = path;
        return this;
    }

    public Signer body(byte[] body) {
        this.body = body;
        return this;
    }

    public Signer header(String name, String value) {
        this.headers.put(new HeaderName(name), value);
        return this;
    }


    public static Signer from(String kid, byte[] privateKeyPem) {
        ECPrivateKey privateKey = InvalidKeyException.evaluate(() ->
                ECKey.parseFromPEMEncodedObjects(new String(privateKeyPem)).toECKey().toECPrivateKey());

        return new Signer(kid, privateKey);
    }

    public String sign() {
        return SignatureException.evaluate(() -> {
                    JWSHeader jwsHeader = JWSHeader.parse(Map.of(
                            "alg", "ES512",
                            "kid", this.kid,
                            "tl_version", "2",
                            "tl_headers", this.headers.keySet().stream().map(HeaderName::getName).collect(Collectors.joining(","))
                            )
                    );

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
