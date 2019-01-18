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
        // Create configuration object
        $configuration = new Configuration();
        $config = $this->processConfiguration($configuration, $configs);

        // If empty encryptor class, use Halite encryptor
        if (in_array($config['encryptor_class'], array_keys(self::SupportedEncryptorClasses))) {
            $config['encryptor_class_full'] = self::SupportedEncryptorClasses[$config['encryptor_class']];
        } else {
            $config['encryptor_class_full'] = self::SupportedEncryptorClasses['Halite'];
        }

        // Set parameters
        $container->setParameter('studio201_doctrine_encrypt.encryptor_class_name', $config['encryptor_class_full']);
        $container->setParameter('studio201_doctrine_encrypt.secret_key_path',$config['secret_directory_path'].'/.'.$config['encryptor_class'].'.key');

        // Load service file
        $loader = new Loader\YamlFileLoader($container, new FileLocator(__DIR__ . '/../Resources/config'));
        $loader->load('services.yml');
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
