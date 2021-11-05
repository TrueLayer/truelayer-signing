package truelayer.signing

internal fun ByteArray.toUrlBase64(): String = java.util.Base64.getUrlEncoder().withoutPadding().encodeToString(this)

internal fun <A, B> Result<A>.flatMap(f: (A) -> Result<B>): Result<B> = this.mapCatching { f(it).getOrThrow() }

internal fun <A, E : Throwable> Result<A>.mapThrowable(f: (Throwable) -> E): Result<A> =
    this.recover { throw f(it) }