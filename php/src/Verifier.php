<?php

declare(strict_types=1);

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
use TrueLayer\Signing\Exceptions\SignatureMustUseDetachedPayloadException;

final class Verifier extends AbstractJws implements IVerifier
{
    private JWSSerializerManager $serializerManager;
    private JWSVerifier $verifier;
    private JWK $jwk;

    /**
     * @var string[]
     */
    private array $requiredHeaders = [];

    /**
     * @param JWK $jwk
     *
     * @return Verifier
     */
    public static function verifyWithKey(JWK $jwk): Verifier
    {
        return new self($jwk);
    }

    /**
     * @param string $pem
     *
     * @return Verifier
     */
    public static function verifyWithPem(string $pem): Verifier
    {
        $jwk = JWKFactory::createFromKey($pem, null, [
            'use' => 'sig',
        ]);

        return new self($jwk);
    }

    /**
     * @param string $pemBase64
     *
     * @return Verifier
     */
    public static function verifyWithPemBase64(string $pemBase64): Verifier
    {
        return self::verifyWithPem(\base64_decode($pemBase64));
    }

    /**
     * @param string $path
     *
     * @return Verifier
     */
    public static function verifyWithPemFile(string $path): Verifier
    {
        $jwk = JWKFactory::createFromKeyFile($path, null, [
            'use' => 'sig',
        ]);

        return new self($jwk);
    }

    /**
     * @param JWK $jwk
     */
    private function __construct(JWK $jwk)
    {
        $this->jwk = $jwk;
        $this->serializerManager = new JWSSerializerManager([new CompactSerializer()]);
        $this->verifier = new JWSVerifier(new AlgorithmManager([new ES512()]));
    }

    /**
     * @param string[] $headers
     *
     * @return $this
     */
    public function requireHeaders(array $headers): Verifier
    {
        \array_push($this->requiredHeaders, ...$headers);

        return $this;
    }

    /**
     * @param string $signature
     *
     * @throws InvalidAlgorithmException
     * @throws InvalidSignatureException
     * @throws InvalidTrueLayerSignatureVersionException
     * @throws RequiredHeaderMissingException
     * @throws RequestPathNotFoundException
     * @throws \Exception
     */
    public function verify(string $signature): void
    {
        $jws = $this->serializerManager
            ->unserialize($signature);

        if (!\is_null($jws->getPayload())) {
            throw new SignatureMustUseDetachedPayloadException();
        }

        $jwsHeaders = $jws->getSignature(TrueLayerSignatures::SIGNATURE_INDEX)->getProtectedHeader();

        if ($jwsHeaders['alg'] !== TrueLayerSignatures::ALGORITHM) {
            throw new InvalidAlgorithmException();
        }

        if ($jwsHeaders['tl_version'] !== TrueLayerSignatures::SIGNING_VERSION) {
            throw new InvalidTrueLayerSignatureVersionException();
        }

        $tlHeaders = !empty($jwsHeaders['tl_headers']) ? \explode(',', $jwsHeaders['tl_headers']) : [];
        $normalisedTlHeaders = Util::normaliseHeaderKeys($tlHeaders);
        foreach ($this->requiredHeaders as $header) {
            if (!\in_array($header, $normalisedTlHeaders, true)) {
                throw new RequiredHeaderMissingException("Signature is missing the {$header} required header");
            }
        }

        if (!$this->verifier->verifyWithKey($jws, $this->jwk, TrueLayerSignatures::SIGNATURE_INDEX, $this->buildPayload($tlHeaders))) {
            throw new InvalidSignatureException();
        }
    }
}
