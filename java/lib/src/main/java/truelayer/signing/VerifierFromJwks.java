package truelayer.signing;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;

import java.security.interfaces.ECPublicKey;
import java.util.Map;

public class VerifierFromJwks extends Verifier {

    private final JWKSet jwkSet;

    protected VerifierFromJwks(JWKSet jwkSet) {
        this.jwkSet = jwkSet;
    }

    @Override
    public void verify(String signature) {
        JWSHeader jwsHeader = SignatureException.evaluate(() -> JWSHeader.parse(JOSEObject.split(signature)[0]));
        Map<HeaderName, String> orderedHeaders = validateSignatureHeader(jwsHeader);

        String keyID = jwsHeader.getKeyID();
        SignatureException.ensure(keyID != null, "missing kid");

        JWK keyByKeyId = jwkSet.getKeyByKeyId(keyID);
        SignatureException.ensure(keyByKeyId != null, "no jwk found with kid");

        ECPublicKey publicKey = buildPublicKey(keyByKeyId);

        Boolean verifiedResult = SignatureException.evaluate(() ->
                JWSObject.parse(signature, new Payload(Utils.buildPayload(orderedHeaders, method, path, body)))
                        .verify(new ECDSAVerifier(publicKey)));

        SignatureException.ensure(verifiedResult, "invalid signature");

    }

    private ECPublicKey buildPublicKey(JWK keyByKeyId) {
        return SignatureException.evaluate(() -> {
            ECKey ecKey = keyByKeyId.toECKey();
            SignatureException.ensure(ecKey.getKeyType().getValue().equals("EC"), "unsupported jwk.kty");
            SignatureException.ensure(ecKey.getAlgorithm().getName().equals("EC"), "unsupported jwk.alg");
            SignatureException.ensure(ecKey.getCurve().equals(Curve.P_521), "unsupported jwk.crv");

            return ecKey.toECPublicKey();
        });
    }
}
