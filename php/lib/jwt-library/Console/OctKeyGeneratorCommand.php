<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Console;

use InvalidArgumentException;
use TrueLayer\Jose\Component\KeyManagement\JWKFactory;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

#[AsCommand(name: 'key:generate:oct', description: 'Generate an octet key (JWK format)',)]
final class OctKeyGeneratorCommand extends GeneratorCommand
{
    protected function configure(): void
    {
        parent::configure();
        $this->addArgument('size', InputArgument::REQUIRED, 'Key size.');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $size = (int) $input->getArgument('size');
        if ($size < 1) {
            throw new InvalidArgumentException('Invalid size');
        }
        $args = $this->getOptions($input);

        $jwk = JWKFactory::createOctKey($size, $args);
        $this->prepareJsonOutput($input, $output, $jwk);

        return self::SUCCESS;
    }
}