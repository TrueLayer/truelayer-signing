package com.truelayer.signing;

import com.nimbusds.jose.JOSEObject;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.Payload;
import com.nimbusds.jose.crypto.ECDSAVerifier;

import java.security.interfaces.ECPublicKey;
import java.text.ParseException;
import java.util.Map;

class VerifierFromPublicKey extends Verifier {

    private final ECPublicKey publicKey;

    protected VerifierFromPublicKey(ECPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public void verify(String signature) throws SignatureException {
        JWSHeader jwsHeader;
        try {
            jwsHeader = JWSHeader.parse(JOSEObject.split(signature)[0]);
        } catch (ParseException e) {
            throw new SignatureException("Failed to parse JWS: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new SignatureException(e);
        }
        Map<HeaderName, String> orderedHeaders = validateSignatureHeader(jwsHeader);

        boolean verifiedResult;
        try {
            verifiedResult = JWSObject.parse(signature, new Payload(Utils.buildPayload(orderedHeaders, method, path, body)))
                    .verify(new ECDSAVerifier(publicKey));
        } catch (ParseException e) {
            throw new SignatureException("Failed to parse JWS: " + e.getMessage(), e);
        } catch (Exception e) {
            throw new SignatureException(e);
        }

        if (!verifiedResult) {
            // try again with/without a trailing slash (#80)
            String path2;
            if (path.endsWith("/")) {
                path2 = path.substring(0, path.length() - 1);
            } else {
                path2 = path + "/";
            }

            try {
                verifiedResult = JWSObject.parse(signature, new Payload(Utils.buildPayload(orderedHeaders, method, path2, body)))
                        .verify(new ECDSAVerifier(publicKey));
            } catch (Exception e) {
                throw new SignatureException(e);
            }
        }

        if (!verifiedResult) {
            throw new SignatureException("invalid signature");
        }
    }

}
