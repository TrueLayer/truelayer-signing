<?php
declare(strict_types=1);

namespace TrueLayer\Signing;

use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\Serializer\CompactSerializer;
use TrueLayer\Signing\Constants\TrueLayerSignatures;
use TrueLayer\Signing\Contracts\Signer as ISigner;

final class Signer extends AbstractJws implements ISigner
{
    private CompactSerializer $serializer;
    private JWSBuilder $builder;
    private JWK $jwk;

    private string $kid;

    /**
     * @param string $kid
     * @param JWK $jwk
     * @return Signer
     */
    public static function signWithKey(string $kid, JWK $jwk): Signer
    {
        return new self($kid, $jwk);
    }

    /**
     * @param string $kid
     * @param string $pem
     * @param string|null $passphrase
     * @return Signer
     */
    public static function signWithPem(string $kid, string $pem, ?string $passphrase): Signer
    {
        $jwk = JWKFactory::createFromKey($pem, $passphrase, [
            'use' => 'sig'
        ]);

        return new self($kid, $jwk);
    }

    /**
     * @param string $kid
     * @param string $pemBase64
     * @param string|null $passphrase
     * @return Signer
     */
    public static function signWithPemBase64(string $kid, string $pemBase64, ?string $passphrase): Signer
    {
        return self::signWithPem($kid, base64_decode($pemBase64), $passphrase);
    }

    /**
     * @param string $kid
     * @param string $path
     * @param string|null $passphrase
     * @return Signer
     */
    public static function signWithPemFile(string $kid, string $path, ?string $passphrase): Signer
    {
        $jwk = JWKFactory::createFromKeyFile($path, $passphrase, [
            'use' => 'sig',
        ]);

        return new self($kid, $jwk);
    }

    /**
     * @param string $kid
     * @param JWK $jwk
     */
    private function __construct(string $kid, JWK $jwk)
    {
        $this->jwk = $jwk;
        $this->kid = $kid;
        $this->serializer = new CompactSerializer();
        $this->builder = new JWSBuilder(new AlgorithmManager([ new ES512() ]));
    }

    /**
     * @return string
     * @throws Exceptions\RequestPathNotFoundException
     */
    public function sign(): string
    {
        $headers = [
            'alg' => TrueLayerSignatures::ALGORITHM,
            'kid' => $this->kid,
            'tl_version' => TrueLayerSignatures::SIGNING_VERSION,
            'tl_headers' => implode(',', array_keys($this->requestHeaders)),
        ];

        $jws = $this->builder
            ->create()
            ->withPayload($this->buildPayload(), true)
            ->addSignature($this->jwk, $headers)
            ->build();

        return $this->serializer
            ->serialize($jws, TrueLayerSignatures::SIGNATURE_INDEX);
    }
}
