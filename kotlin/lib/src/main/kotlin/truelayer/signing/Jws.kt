package truelayer.signing

import com.nimbusds.jose.*
import com.nimbusds.jose.crypto.ECDSASigner
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.util.Base64URL
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey

internal fun signEs512(
    key: ECPrivateKey,
    kid: String,
    headers: Map<HeaderName, String>,
    method: String,
    path: String,
    body: ByteArray
): Result<String> =
    InvalidSignatureException.evaluate {
        val json = Json.encodeToString(
            mapOf(
                "alg" to "ES512",
                "kid" to kid,
                "tl_version" to "2",
                "tl_headers" to headers.keys.joinToString { it.name }
            )
        ).toByteArray()

        val jwsObject = JWSObject(
            JWSHeader.parse(Base64URL(json.toUrlBase64())),
            Payload(Base64URL(buildPayload(headers, method, path, body)))
        )

        jwsObject.sign(ECDSASigner(key))
        jwsObject.serialize(true)
    }

internal fun verifyTlSignature(
    signature: String,
    publicKey: ECPublicKey,
    requiredHeaders: HashSet<String>,
    method: String,
    path: String,
    body: ByteArray,
    headers: Map<HeaderName, String>
): Result<Boolean> {
    val header = InvalidSignatureException.evaluate { JWSHeader.parse(JOSEObject.split(signature)[0]) }.getOrThrow()
    val signatureHeaderNames = validSignatureHeaders(header, requiredHeaders).getOrThrow()
    return InvalidSignatureException.evaluate {
        val orderedHeaders =
            signatureHeaderNames.fold(LinkedHashMap<HeaderName, String>(0)) { acc, curr ->
                val value: String? = headers[HeaderName((curr))]
                if (value != null) {
                    acc[HeaderName(curr)] = value
                }
                acc
            }

        val detachedPayload = Payload(Base64URL(buildPayload(orderedHeaders, method, path, body)))
        JWSObject.parse(signature, detachedPayload).verify(ECDSAVerifier(publicKey))
    }
}

private fun buildPayload(
    headers: Map<HeaderName, String>,
    method: String,
    path: String,
    body: ByteArray
): String {
    val entries = headers.entries
    val headersBytes: ByteArray = entries.fold(ByteArray(0)) { acc, entry ->
        acc + entry.key.name.toByteArray() +
                ": ".toByteArray() +
                entry.value.toByteArray() +
                "\n".toByteArray()
    }

    val payload = method.uppercase().toByteArray() +
            " ".toByteArray() +
            path.toByteArray() +
            "\n".toByteArray() +
            headersBytes +
            body

    return payload.toUrlBase64()
}

private fun validSignatureHeaders(
    signatureHeaders: JWSHeader,
    requiredHeaders: HashSet<String>
): Result<List<String>> = runCatching {
    InvalidSignatureException.ensure({ signatureHeaders.algorithm.equals(JWSAlgorithm.ES512) }, "unexpected header algorithm")

    InvalidSignatureException.ensure(
        { signatureHeaders.getCustomParam("tl_version").toString() == "2" },
        "only version 2 is allowed"
    )

    val signatureHeaderNames = signatureHeaders.getCustomParam("tl_headers").toString().split(",").map { it.trim() }
    InvalidSignatureException.ensure(
        { requiredHeaders.all { rHeader -> signatureHeaderNames.any { it.contains(rHeader, true) } } },
        "missing required header"
    )

    signatureHeaderNames
}
