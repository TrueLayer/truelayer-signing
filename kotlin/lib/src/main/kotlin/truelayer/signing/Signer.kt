package truelayer.signing

import java.security.interfaces.ECPrivateKey


class Signer private constructor(
    private val kid: String,
    private val private_key: ECPrivateKey,
) {
    private var body: ByteArray = ByteArray(0)

    private var method: String = "POST"

    private var path: String = ""

    private var headers: LinkedHashMap<HeaderName, String> = linkedMapOf()

    fun body(body: ByteArray): Signer {
        this.body = body
        return this
    }

    fun method(method: String): Signer {
        this.method = method
        return this
    }

    fun path(path: String): Signer {
        this.path = path
        return this
    }

    fun header(name: String, value: String): Signer {
        this.headers[HeaderName(name)] = value
        return this
    }

    fun sign(): String {
        return signEs512(private_key, kid, headers, method, path, body).getOrThrow()
    }

    companion object {
        @JvmStatic
        fun from(kid: String, privateKeyPem: ByteArray): Signer {
            val privateKey = parseEcPrivateKey(privateKeyPem).getOrThrow()
            return Signer(kid, privateKey)
        }
    }
}


