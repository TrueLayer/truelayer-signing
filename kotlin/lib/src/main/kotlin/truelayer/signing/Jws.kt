package truelayer.signing

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.util.Base64URL
import java.security.interfaces.ECPublicKey

internal fun validateSignature(
    signature: String,
    signatureHeaderNames: List<String>,
    headers: Map<HeaderName, String>,
    method: String,
    path: String,
    body: ByteArray,
    publicKey: ECPublicKey
): Result<Unit> {
    val orderedHeaders =
        signatureHeaderNames.fold(LinkedHashMap<HeaderName, String>(0)) { acc, curr ->
            val value: String? = headers[HeaderName((curr))]
            if (value != null) {
                acc[HeaderName(curr)] = value
            }
            acc
        }

    return InvalidSignatureException.evaluate {
        JWSObject.parse(signature, Payload(Base64URL(buildPayload(orderedHeaders, method, path, body))))
            .verify(ECDSAVerifier(publicKey))
    }.flatMap { verified -> InvalidSignatureException.ensure({ verified }, "jws body mismatch") }
}

internal fun validateSignatureHeaders(
    signatureHeaders: JWSHeader,
    requiredHeaders: HashSet<String>
): Result<List<String>> =
    validateAlghoritm(signatureHeaders)
        .flatMap { validateSignatureHeaders(signatureHeaders) }
        .flatMap { verifyRequiredHeaders(signatureHeaders, requiredHeaders) }


private fun verifyRequiredHeaders(
    signatureHeaders: JWSHeader,
    requiredHeaders: HashSet<String>
): Result<List<String>> {
    val signatureHeaderNames = signatureHeaders.getCustomParam("tl_headers").toString().split(",").map { it.trim() }
    return InvalidSignatureException.ensure(
        { requiredHeaders.all { rHeader -> signatureHeaderNames.any { it.contains(rHeader, true) } } },
        "missing required header"
    ).map { signatureHeaderNames }
}

private fun validateSignatureHeaders(signatureHeaders: JWSHeader): Result<Unit> =
    InvalidSignatureException.ensure(
        { signatureHeaders.getCustomParam("tl_version").toString() == "2" },
        "only version 2 is allowed"
    )

private fun validateAlghoritm(signatureHeaders: JWSHeader): Result<Unit> =
    InvalidSignatureException.ensure(
        { signatureHeaders.algorithm.equals(JWSAlgorithm.ES512) },
        "unexpected header algorithm"
    )

internal fun buildPayload(
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

