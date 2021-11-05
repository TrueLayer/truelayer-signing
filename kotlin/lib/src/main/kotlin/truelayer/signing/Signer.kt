package truelayer.signing

import java.security.interfaces.ECPrivateKey

/**
 * Builder to generate a Tl-Signature header value using a private key.
 */
class Signer private constructor(
    private val kid: String,
    private val private_key: ECPrivateKey,
) {
    private var body: ByteArray = ByteArray(0)

    private var method: String = "POST"

    private var path: String = ""

    private var headers: LinkedHashMap<HeaderName, String> = linkedMapOf()

    /**
     * Add the full request body. Note: This *must* be identical to what is sent with the request.
     */
    fun body(body: ByteArray): Signer {
        this.body = body
        return this
    }

    /**
     * Add the request method, defaults to `"POST"` if unspecified.
     */
    fun method(method: String): Signer {
        this.method = method
        return this
    }

    /**
     * Add the request absolute path starting with a leading `/` and without any trailing slashes.
     */
    fun path(path: String): Signer {
        this.path = path
        return this
    }

    /**
     * Add a header name and value. May be called multiple times to add multiple different headers.
     * Warning: Only a single value per header name is supported.
     */
    fun header(name: String, value: String): Signer {
        this.headers[HeaderName(name)] = value
        return this
    }

    /**
     * Produce a JWS `Tl-Signature` v2 header value
     * @throws InvalidSignatureException
     */
    fun sign(): String {
        return signEs512(private_key, kid, headers, method, path, body).getOrThrow()
    }

    companion object {
        /**
         * Start building a request Tl-Signature header value using private key
         * RFC 7468 PEM-encoded data and the key's kid.
         * @param kid key identifier of the private key
         * @param privateKeyPem the privateKey RFC 7468 PEM-encoded
         * @throws InvalidKeyException if the provided key is invalid
         */
        @JvmStatic
        fun from(kid: String, privateKeyPem: ByteArray): Signer {
            return Signer(kid, parseEcPrivateKey(privateKeyPem).getOrThrow())
        }
    }
}


