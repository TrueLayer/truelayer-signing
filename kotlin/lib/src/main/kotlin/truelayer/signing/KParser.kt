package truelayer.signing

import com.nimbusds.jose.jwk.ECKey
import java.security.interfaces.ECPrivateKey
import java.security.interfaces.ECPublicKey


internal fun parseEcPrivateKey(privateKey: ByteArray): Result<ECPrivateKey> = InvalidKeyException.evaluate {
    ECKey.parseFromPEMEncodedObjects(privateKey.decodeToString()).toECKey().toECPrivateKey()
}

internal fun parseEcPublicKey(publicKey: ByteArray): Result<ECPublicKey> = InvalidKeyException.evaluate {
    ECKey.parseFromPEMEncodedObjects(publicKey.decodeToString()).toECKey().toECPublicKey()
}
