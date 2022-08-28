package com.truelayer.signing;

@FunctionalInterface
public interface CheckedSupplier<T> {
    T get() throws Exception;
}
