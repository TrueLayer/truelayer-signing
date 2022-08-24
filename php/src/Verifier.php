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
use TrueLayer\Signing\Exceptions\InvalidArgumentException;
use TrueLayer\Signing\Exceptions\InvalidSignatureException;
use TrueLayer\Signing\Exceptions\InvalidTrueLayerSignatureVersionException;
use TrueLayer\Signing\Exceptions\RequestPathNotFoundException;
use TrueLayer\Signing\Exceptions\RequiredHeaderMissingException;
use TrueLayer\Signing\Exceptions\SignatureMustUseDetachedPayloadException;

final class Verifier extends AbstractJws implements IVerifier
{
    /**
     * @var JWSSerializerManager
     */
    private JWSSerializerManager $serializerManager;

    /**
     * @var JWSVerifier
     */
    private JWSVerifier $verifier;

    /**
     * @var array<JWK>
     */
    private array $jwks;

    /**
     * @var string[]
     */
    private array $requiredHeaders = [];

    /**
     * @param array<string, string> ...$jsonObjects
     *
     * @throws InvalidArgumentException
     *
     * @return IVerifier
     */
    public static function verifyWithJsonKeys(array ...$jsonObjects): IVerifier
    {
        $jwks = [];
        try {
            foreach ($jsonObjects as $jsonObject) {
                $encoded = \json_encode($jsonObject);
                if (!\is_string($encoded)) {
                    throw new InvalidArgumentException('One or multiple keys are invalid');
                }

                $jwks[] = JWK::createFromJson($encoded);
            }
        } catch (\InvalidArgumentException $e) {
            throw new InvalidArgumentException('One or multiple keys are invalid');
        }

        return new self($jwks);
    }

    /**
     * @param JWK ...$jwks
     *
     * @return IVerifier
     */
    public static function verifyWithKeys(JWK ...$jwks): IVerifier
    {
        return new self($jwks);
    }

    /**
     * @param JWK $jwk
     *
     * @return IVerifier
     */
    public static function verifyWithKey(JWK $jwk): IVerifier
    {
        return self::verifyWithKeys($jwk);
    }

    /**
     * @param string ...$pems
     *
     * @throws InvalidArgumentException
     *
     * @return IVerifier
     */
    public static function verifyWithPem(string ...$pems): IVerifier
    {
        $jwks = [];
        try {
            foreach ($pems as $pem) {
                $jwks[] = JWKFactory::createFromKey($pem, null, [
                    'use' => 'sig',
                ]);
            }
        } catch (\Exception $e) {
            throw new InvalidArgumentException('One or multiple PEM keys could not be deserialized');
        }

        return new self($jwks);
    }

    /**
     * @param string ...$pemsBase64
     *
     * @throws InvalidArgumentException
     *
     * @return IVerifier
     */
    public static function verifyWithPemBase64(string ...$pemsBase64): IVerifier
    {
        $decodedPems = [];
        foreach ($pemsBase64 as $pemBase64) {
            $decodedPems[] = \base64_decode($pemBase64);
        }

        return self::verifyWithPem(...$decodedPems);
    }

    /**
     * @param string ...$paths
     *
     * @throws InvalidArgumentException
     *
     * @return IVerifier
     */
    public static function verifyWithPemFile(string ...$paths): IVerifier
    {
        $jwks = [];

        try {
            foreach ($paths as $path) {
                $jwks[] = JWKFactory::createFromKeyFile($path, null, [
                    'use' => 'sig',
                ]);
            }
        } catch (\Exception $e) {
            throw new InvalidArgumentException('One or multiple files contain invalid keys');
        }

        return new self($jwks);
    }

    /**
     * @param array<JWK> $jwks
     */
    private function __construct(array $jwks)
    {
        $this->jwks = $jwks;
        $this->serializerManager = new JWSSerializerManager([new CompactSerializer()]);
        $this->verifier = new JWSVerifier(new AlgorithmManager([new ES512()]));
    }

    /**
     * @param string[] $headers
     *
     * @return IVerifier
     */
    public function requireHeaders(array $headers): IVerifier
    {
        $lowercaseHeaders = \array_map('strtolower', $headers);

        \array_push($this->requiredHeaders, ...$lowercaseHeaders);

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

        if (!empty($jwsHeaders['tl_version']) && $jwsHeaders['tl_version'] !== TrueLayerSignatures::SIGNING_VERSION) {
            throw new InvalidTrueLayerSignatureVersionException();
        }

        if (empty($jwsHeaders['kid'])) {
            throw new InvalidSignatureException('The kid is missing from the signature headers');
        }

        $tlHeaders = !empty($jwsHeaders['tl_headers']) ? \explode(',', $jwsHeaders['tl_headers']) : [];

        if (!empty($this->requestHeaders)) {
            $lowercaseTlHeaders = \array_map('strtolower', $tlHeaders);
            foreach ($this->requiredHeaders as $requiredHeader) {
                if (!\in_array($requiredHeader, $lowercaseTlHeaders, true)) {
                    throw new RequiredHeaderMissingException("Signature is missing the {$requiredHeader} required header");
                }
            }
        }

        foreach ($this->jwks as $jwk) {
            if ($this->verifier->verifyWithKey($jws, $jwk, TrueLayerSignatures::SIGNATURE_INDEX, $this->buildPayload($tlHeaders))) {
                return;
            }
            if ($this->verifier->verifyWithKey($jws, $jwk, TrueLayerSignatures::SIGNATURE_INDEX, $this->buildPayload($tlHeaders, true))) {
                return;
            }
        }

        throw new InvalidSignatureException();
    }
}
