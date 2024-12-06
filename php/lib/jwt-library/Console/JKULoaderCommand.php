<?php

declare(strict_types=1);

namespace TrueLayer\Jose\Component\Console;

use InvalidArgumentException;
use TrueLayer\Jose\Component\KeyManagement\JKUFactory;

use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Input\InputArgument;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use function is_string;

#[AsCommand(name: 'keyset:load:jku', description: 'Loads a key set from an url.',)]
final class JKULoaderCommand extends ObjectOutputCommand
{
    public function __construct(
        private readonly JKUFactory $jkuFactory,
        ?string $name = null
    ) {
        parent::__construct($name);
    }

    protected function configure(): void
    {
        parent::configure();
        $this->setHelp('This command will try to get a key set from an URL. The distant key set is a JWKSet.')
            ->addArgument('url', InputArgument::REQUIRED, 'The URL');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $url = $input->getArgument('url');
        if (! is_string($url)) {
            throw new InvalidArgumentException('Invalid URL');
        }
        $result = $this->jkuFactory->loadFromUrl($url);
        $this->prepareJsonOutput($input, $output, $result);

        return self::SUCCESS;
    }
}
