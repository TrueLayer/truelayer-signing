package truelayer.signing

class Verifier private constructor (
    private val publicKey: ByteArray
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
        val publicKey = parseEcPublicKey(this.publicKey).getOrThrow()
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
        fun from(publicKey: ByteArray): Verifier {
            return Verifier(publicKey)
        }
    }
}