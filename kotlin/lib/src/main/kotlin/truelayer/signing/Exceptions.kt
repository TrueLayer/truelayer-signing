package truelayer.signing

class InvalidKeyException private constructor(message: String, cause: Throwable) : Exception(message, cause) {
    companion object {
        internal fun <T> evaluate(block: () -> T): Result<T> = runCatching {
            block()
        }.mapThrowable { e -> InvalidKeyException("Invalid Key: ${e.message}", e) }
    }
}

class InvalidSignatureException : Exception {
    private constructor(message: String, cause: Throwable) : super(message, cause)
    private constructor(message: String) : super(message)

    companion object {
        internal fun ensure(predicate: () -> Boolean, message: String): Result<Unit> =
            if (predicate()) {
                Result.success(Unit)
            } else {
                Result.failure(InvalidSignatureException("JWS signing/verification failed: $message"))
            }

        internal fun <T> evaluate(block: () -> T) = runCatching {
            block()
        }.mapThrowable { e ->
            InvalidSignatureException(
                "JWS signing/verification failed: ${e.message}",
                e
            )
        }
    }
}