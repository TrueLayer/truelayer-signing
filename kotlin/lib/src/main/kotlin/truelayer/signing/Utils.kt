package truelayer.signing

internal fun <T, E : Throwable> Result.Companion.evaluate(block: () -> T, throwException: (Throwable) -> E): Result<T> =
    runCatching {
        try {
            block()
        } catch (e: Exception) {
            throw throwException(e)
        }
    }

internal fun ByteArray.toUrlBase64(): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(this)