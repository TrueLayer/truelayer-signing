package truelayer.signing

import java.security.interfaces.ECPublicKey

class Verifier private constructor (
    private val publicKey: ECPublicKey
) {
    private var method: String = ""

    private var path: String = ""

    private var body: ByteArray = ByteArray(0)

    private var headers: HashMap<HeaderName, String> = linkedMapOf()

    private var requiredHeaders: HashSet<String> = HashSet()


    fun method(method: String): Verifier {
        this.method = method
        return this
    }

    fun path(path: String): Verifier {
        this.path = path
        return this
    }

    fun header(name: String, value: String): Verifier {
        this.headers[HeaderName(name)] = value
        return this
    }

    fun body(body: ByteArray): Verifier {
        this.body = body
        return this
    }

    fun requiredHeader(name: String): Verifier {
        this.requiredHeaders.add(name)
        return this
    }

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
        @JvmStatic
        fun from(publicKeyPem: ByteArray): Verifier {
            return Verifier(parseEcPublicKey(publicKeyPem).getOrThrow())
        }
    }
}