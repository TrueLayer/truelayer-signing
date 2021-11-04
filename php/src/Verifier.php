<?php

namespace TrueLayer\Signing;

use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\JWSVerifier;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Jose\Component\Signature\Serializer\JWSSerializerManager;
use TrueLayer\Signing\Constants\TrueLayerSignatures;
use TrueLayer\Signing\Contracts\Verifier as IVerifier;
use TrueLayer\Signing\Exceptions\InvalidAlgorithmException;
use TrueLayer\Signing\Exceptions\InvalidSignatureException;
use TrueLayer\Signing\Exceptions\InvalidTrueLayerSignatureVersionException;
use TrueLayer\Signing\Exceptions\RequestPathNotFoundException;
use TrueLayer\Signing\Exceptions\RequiredHeaderMissingException;
use TrueLayer\Signing\Exceptions\TrueLayerHeadersNotFoundException;

final class Verifier extends AbstractJws implements IVerifier
{
    protected JWSSerializerManager $serializerManager;
    protected JWSVerifier $verifier;
    protected JWK $jwk;

    protected string $kid;

    protected array $required_headers = [];

    public static function verifyWithPem(string $pem): Verifier
    {
        $jwk = JWKFactory::createFromKey($pem, null, [
            'use' => 'sig'
        ]);

        return new self($jwk);
    }

    public static function verifyWithPemBase64(string $pemBase64): Verifier
    {
        return self::verifyWithPem(base64_decode($pemBase64));
    }

    public static function verifyWithPemFile(string $path): Verifier
    {
        $jwk = JWKFactory::createFromKeyFile($path, null, [
            'use' => 'sig',
        ]);

        return new self($jwk);
    }

    protected function __construct(JWK $jwk)
    {
        $this->jwk = $jwk;
        $this->serializerManager = new JWSSerializerManager([ new CompactSerializer() ]);
        $this->verifier = new JWSVerifier(new AlgorithmManager([ new ES512() ]));
    }

    public function requireHeaders(array $headers): Verifier
    {
        array_push($this->required_headers, ...$headers);
        return $this;
    }

    /**
     * @param string $signature
     * @throws InvalidAlgorithmException
     * @throws InvalidSignatureException
     * @throws InvalidTrueLayerSignatureVersionException
     * @throws TrueLayerHeadersNotFoundException
     * @throws RequiredHeaderMissingException
     * @throws RequestPathNotFoundException
     */
    public function verify(string $signature): void
    {
        $jws = $this->serializerManager
            ->unserialize($signature);

        $jwsHeaders = $jws->getSignature(TrueLayerSignatures::SIGNATURE_INDEX)->getProtectedHeader();

        if ($jwsHeaders['alg'] !== TrueLayerSignatures::ALGORITHM) {
            throw new InvalidAlgorithmException();
        }

        if ($jwsHeaders['tl_version'] !== TrueLayerSignatures::SIGNING_VERSION) {
            throw new InvalidTrueLayerSignatureVersionException();
        }

        foreach ($this->required_headers as $header) {
            if (!in_array($header, $jwsHeaders['tl_headers'])) {
                throw new RequiredHeaderMissingException("Signature is missing the {$header} required header");
            }
        }

        if (! $this->verifier->verifyWithKey($jws, $this->jwk, TrueLayerSignatures::SIGNATURE_INDEX, $this->buildPayload())) {
            throw new InvalidSignatureException();
        }
    }
}
