package com.truelayer.signing;

/**
 * Sign/verification error
 */
public class SignatureException extends RuntimeException {

    public SignatureException(String failureMessage) {
        super(failureMessage);
    }

    public SignatureException(String message, Exception e) {
        super(message, e);
    }

    public SignatureException(Exception e) {
        super(e);
    }

    protected static void ensure(boolean condition, String failureMessage) {
        if (!condition)
            throw new SignatureException(failureMessage);
    }
}
