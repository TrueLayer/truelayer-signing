<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Console;

use InvalidArgumentException;
use TrueLayer\Jose\Component\KeyManagement\JWKFactory;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use function is_string;

#[AsCommand(name: 'key:generate:okp', description: 'Generate an Octet Key Pair key (JWK format)',)]
final class OkpKeyGeneratorCommand extends GeneratorCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this->addArgument('curve', InputArgument::REQUIRED, 'Curve of the key.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $curve = $input->getArgument('curve');
        if (! is_string($curve)) {
            throw new InvalidArgumentException('Invalid curve');
        }
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createOKPKey($curve, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return self::SUCCESS;
    }
}