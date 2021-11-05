package truelayer.signing

import java.security.interfaces.ECPublicKey

/**
 * Builder to verify a request against a `Tl-Signature` header using a public key.
 */
class Verifier private constructor (
    private val publicKey: ECPublicKey
) {
    private var method: String = ""

    private var path: String = ""

    private var body: ByteArray = ByteArray(0)

    private var headers: HashMap<HeaderName, String> = linkedMapOf()

    private var requiredHeaders: HashSet<String> = HashSet()


    /**
     * Add the request method.
     */
    fun method(method: String): Verifier {
        this.method = method
        return this
    }

    /**
     * Add the request absolute path starting with a leading `/` and without any trailing slashes.
     */
    fun path(path: String): Verifier {
        this.path = path
        return this
    }

    /**
     * Add a header name and value.
     * May be called multiple times to add multiple different headers.
     * Warning: Only a single value per header name is supported.
     */
    fun header(name: String, value: String): Verifier {
        this.headers[HeaderName(name)] = value
        return this
    }

    /**
     * Add the full unmodified request body.
     */
    fun body(body: ByteArray): Verifier {
        this.body = body
        return this
    }

    /**
     * Require a header name that must be included in the `Tl-Signature`.
     * May be called multiple times to add multiple required headers.
     */
    fun requiredHeader(name: String): Verifier {
        this.requiredHeaders.add(name)
        return this
    }

    /**
     * Verify the given `Tl-Signature` header value.
     * @param signature the given `TL-signature`
     * @return Boolean true id verification succeded or false if unsuccessful
     * @throws InvalidSignatureException if Signature is invalid
     */
    fun verify(signature: String): Boolean {
        return verifyTlSignature(
            signature,
            publicKey,
            this.requiredHeaders,
            this.method,
            this.path,
            this.body,
            this.headers
        ).getOrThrow()
    }

    companion object {
        /**
         * Start building a `Tl-Signature` header verifier using public key RFC 7468 PEM-encoded data.
         * @param publicKeyPem the public key 7468 PEM-encoded data
         * @throws InvalidKeyException it the provided key is invalid
         */
        @JvmStatic
        fun from(publicKeyPem: ByteArray): Verifier {
            return Verifier(parseEcPublicKey(publicKeyPem).getOrThrow())
        }
    }
}