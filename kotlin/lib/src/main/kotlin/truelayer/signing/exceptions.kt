package truelayer.signing

internal class InvalidKeyException(message: String, cause: Throwable) : Exception(message, cause) {
    companion object {
        fun <T> evaluate(block: () -> T): Result<T> =
            Result.evaluate(block) { e -> InvalidKeyException("Invalid Key: ${e.message}", e) }
    }
}

internal class JwsErrorException : Exception {
    constructor(message: String, cause: Throwable) : super(message, cause)
    constructor(message: String) : super(message)

    companion object {
        fun ensure(predicate: () -> Boolean, message: String) {
            if (predicate()) {
                return
            } else {
                throw JwsErrorException("JWS signing/verification failed: $message")
            }
        }

        fun <T> evaluate(block: () -> T) =
            Result.evaluate(block) { e -> JwsErrorException("JWS signing/verification failed: ${e.message}", e) }
    }
}