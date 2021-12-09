<?php

declare(strict_types=1);

namespace TrueLayer\Signing;

use Exception;
use Jose\Component\Core\AlgorithmManager;
use Jose\Component\Core\JWK;
use Jose\Component\KeyManagement\JWKFactory;
use Jose\Component\Signature\Algorithm\ES512;
use Jose\Component\Signature\JWSBuilder;
use Jose\Component\Signature\Serializer\CompactSerializer;
use Psr\Http\Message\RequestInterface;
use TrueLayer\Signing\Constants\CustomHeaders;
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
     * @param JWK    $jwk
     *
     * @return Signer
     */
    public static function signWithKey(string $kid, JWK $jwk): Signer
    {
        return new self($kid, $jwk);
    }

    /**
     * @param string      $kid
     * @param string      $pem
     * @param string|null $passphrase
     *
     * @return Signer
     */
    public static function signWithPem(string $kid, string $pem, ?string $passphrase = null): Signer
    {
        $jwk = JWKFactory::createFromKey($pem, $passphrase, [
            'use' => 'sig',
        ]);

        return new self($kid, $jwk);
    }

    /**
     * @param string      $kid
     * @param string      $pemBase64
     * @param string|null $passphrase
     *
     * @return Signer
     */
    public static function signWithPemBase64(string $kid, string $pemBase64, ?string $passphrase = null): Signer
    {
        return self::signWithPem($kid, \base64_decode($pemBase64), $passphrase);
    }

    /**
     * @param string      $kid
     * @param string      $path
     * @param string|null $passphrase
     *
     * @return Signer
     */
    public static function signWithPemFile(string $kid, string $path, ?string $passphrase = null): Signer
    {
        $jwk = JWKFactory::createFromKeyFile($path, $passphrase, [
            'use' => 'sig',
        ]);

        return new self($kid, $jwk);
    }

    /**
     * @param string $kid
     * @param JWK    $jwk
     */
    private function __construct(string $kid, JWK $jwk)
    {
        $this->jwk = $jwk;
        $this->kid = $kid;
        $this->serializer = new CompactSerializer();
        $this->builder = new JWSBuilder(new AlgorithmManager([new ES512()]));
    }

    /**
     * @throws Exceptions\RequestPathNotFoundException
     * @throws Exception
     *
     * @return string
     */
    public function sign(): string
    {
        $tlHeaders = \array_keys(Util::normaliseHeaders($this->requestHeaders));

        $headers = [
            'alg' => TrueLayerSignatures::ALGORITHM,
            'kid' => $this->kid,
            'tl_version' => TrueLayerSignatures::SIGNING_VERSION,
            'tl_headers' => \implode(',', $tlHeaders),
        ];

        $jws = $this->builder
            ->create()
            ->withPayload($this->buildPayload($tlHeaders), true)
            ->addSignature($this->jwk, $headers)
            ->build();

        return $this->serializer
            ->serialize($jws, TrueLayerSignatures::SIGNATURE_INDEX);
    }

    /**
     * @param RequestInterface $request
     *
     * @throws Exceptions\RequestPathNotFoundException
     *
     * @return RequestInterface
     */
    public function addSignatureHeader(RequestInterface $request): RequestInterface
    {
        $signature = $this->method($request->getMethod())
            ->path($request->getUri()->getPath())
            ->body((string) $request->getBody())
            ->headers(Util::flattenHeaders($request->getHeaders()))
            ->sign();

        return $request->withHeader(CustomHeaders::SIGNATURE, $signature);
    }
}
