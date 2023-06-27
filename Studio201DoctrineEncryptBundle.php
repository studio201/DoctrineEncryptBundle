<?php

namespace Studio201\DoctrineEncryptBundle;

use Symfony\Component\HttpKernel\Bundle\Bundle;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Studio201\DoctrineEncryptBundle\DependencyInjection\DoctrineEncryptExtension;
use Studio201\DoctrineEncryptBundle\DependencyInjection\Compiler\RegisterServiceCompilerPass;

class Studio201DoctrineEncryptBundle extends Bundle
{
    public function build(ContainerBuilder $container)
    {
        parent::build($container);
        $container->addCompilerPass(new RegisterServiceCompilerPass(), PassConfig::TYPE_AFTER_REMOVING);
    }

    public function getContainerExtension(): ?Symfony\Component\DependencyInjection\Extension\ExtensionInterface
    {
        return new DoctrineEncryptExtension();
    }
}
