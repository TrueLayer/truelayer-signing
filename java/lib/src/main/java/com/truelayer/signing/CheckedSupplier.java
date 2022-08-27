package com.truelayer.signing;

public interface CheckedSupplier<T> {
    T get() throws Exception;
}
