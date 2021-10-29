package truelayer.signing

import org.bouncycastle.jce.provider.BouncyCastleProvider
import org.bouncycastle.jce.spec.ECPrivateKeySpec
import org.bouncycastle.util.io.pem.PemReader
import java.io.ByteArrayInputStream
import java.io.InputStreamReader
import java.security.KeyFactory
import java.security.Security
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey
import java.security.spec.X509EncodedKeySpec


internal fun parseEcPrivateKey(privateKey: ByteArray): Result<ECPrivateKey> = InvalidKeyException.evaluate {
    Security.addProvider(BouncyCastleProvider())
    val pemObject = PemReader(InputStreamReader(ByteArrayInputStream(privateKey))).readPemObject()

    val kf = KeyFactory.getInstance("EC")
    val asn1PrivKey = org.bouncycastle.asn1.sec.ECPrivateKey.getInstance(pemObject.content)
    val parameterSpec = org.bouncycastle.jce.ECNamedCurveTable.getParameterSpec("secp521r1")
    val keySpec = ECPrivateKeySpec(asn1PrivKey.key, parameterSpec)

    kf.generatePrivate(keySpec) as ECPrivateKey
}

internal fun parseEcPublicKey(publicKey: ByteArray): Result<ECPublicKey> = InvalidKeyException.evaluate {
    Security.addProvider(BouncyCastleProvider())
    val pemObject = PemReader(InputStreamReader(ByteArrayInputStream(publicKey))).readPemObject()
    KeyFactory.getInstance("EC").generatePublic(X509EncodedKeySpec(pemObject.content)) as ECPublicKey
}
