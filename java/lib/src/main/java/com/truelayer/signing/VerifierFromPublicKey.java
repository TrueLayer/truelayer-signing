package com.truelayer.signing;

import com.nimbusds.jose.*;
import com.nimbusds.jose.crypto.ECDSAVerifier;

import java.security.interfaces.ECPublicKey;
import java.util.*;

class VerifierFromPublicKey extends Verifier{

    private final ECPublicKey publicKey;

    protected VerifierFromPublicKey(ECPublicKey publicKey) {
        this.publicKey = publicKey;
    }

    @Override
    public void verify(String signature) {
        JWSHeader jwsHeader = SignatureException.evaluate(() -> JWSHeader.parse(JOSEObject.split(signature)[0]));
        Map<HeaderName, String> orderedHeaders = validateSignatureHeader(jwsHeader);

        Boolean verifiedResult = SignatureException.evaluate(() ->
                JWSObject.parse(signature, new Payload(Utils.buildPayload(orderedHeaders, method, path, body)))
                        .verify(new ECDSAVerifier(publicKey)));

        if (!verifiedResult) {
            // try again with/without a trailing slash (#80)
            String path2;
            if (path.endsWith("/")) {
                path2 = path.substring(0, path.length() - 1);
            } else {
                path2 = path + "/";
            }
            verifiedResult = SignatureException.evaluate(() ->
                    JWSObject.parse(signature, new Payload(Utils.buildPayload(orderedHeaders, method, path2, body)))
                            .verify(new ECDSAVerifier(publicKey)));
        }

        SignatureException.ensure(verifiedResult, "invalid signature");
    }

}
