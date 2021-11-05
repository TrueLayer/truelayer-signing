package truelayer.signing

class InvalidKeyException private constructor(message: String, cause: Throwable) : Exception(message, cause) {
    companion object {
        internal fun <T> evaluate(block: () -> T): Result<T> =
            Result.evaluate(block) { e -> InvalidKeyException("Invalid Key: ${e.message}", e) }
    }
}

class InvalidSignatureException : Exception {
    private constructor(message: String, cause: Throwable) : super(message, cause)
    private constructor(message: String) : super(message)

    companion object {
        internal fun ensure(predicate: () -> Boolean, message: String) {
            if (predicate()) {
                return
            } else {
                throw InvalidSignatureException("JWS signing/verification failed: $message")
            }
        }

        internal fun <T> evaluate(block: () -> T) =
            Result.evaluate(block) { e -> InvalidSignatureException("JWS signing/verification failed: ${e.message}", e) }
    }
}