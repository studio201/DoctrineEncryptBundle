<?php

namespace Studio201\DoctrineEncryptBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\HttpKernel\DependencyInjection\Extension;
use Symfony\Component\DependencyInjection\Loader;

/**
 * Initialization of bundle.
 *
 * This is the class that loads and manages your bundle configuration
 *
 * To learn more see {@link http://symfony.com/doc/current/cookbook/bundles/extension.html}
 */
class DoctrineEncryptExtension extends Extension
{
    const SupportedEncryptorClasses = array(
        'Defuse' => 'Studio201\DoctrineEncryptBundle\Encryptors\DefuseEncryptor',
        'Halite' => 'Studio201\DoctrineEncryptBundle\Encryptors\HaliteEncryptor',
    );

    /**
     * {@inheritDoc}
     */
    public function load(array $configs, ContainerBuilder $container)
    {
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);
        $services = array('orm' => 'orm-services');
        $supportedEncryptorClasses = array('aes256' => 'Studio201\DoctrineEncryptBundle\Encryptors\OldCoreEncryptor');

        if (empty($config['secret_key'])) {
            if ($container->hasParameter('secret')) {
                $config['secret_key'] = $container->getParameter('secret');
            } else {
                throw new \RuntimeException('You must provide "secret_key" for DoctrineEncryptBundle or "secret" for framework');
            }
        }

        if (!empty($config['encryptor_class'])) {
            $encryptorFullName = $config['encryptor_class'];
        } else {
            $encryptorFullName = $supportedEncryptorClasses[$config['encryptor']];
        }
        $container->setParameter('studio201_doctrine_encrypt.encryptor_class_name', $encryptorFullName);
        $container->setParameter('studio201_doctrine_encrypt.secret_key', $config['secret_key']);

        $loader = new Loader\XmlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load(sprintf('%s.xml', $services[$config['db_driver']]));
    }

    /**
     * Get alias for configuration
     *
     * @return string
     */
    public function getAlias()
    {
        return 'studio201_doctrine_encrypt';
    }
}
