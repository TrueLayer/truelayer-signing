package com.truelayer.signing;

/**
 * Key error
 */
public class KeyException extends RuntimeException {
    public KeyException(Exception e) {
        super(e);
    }
}
