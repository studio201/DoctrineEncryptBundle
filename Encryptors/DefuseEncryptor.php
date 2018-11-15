<?php

namespace Studio201\DoctrineEncryptBundle\Encryptors;

use Symfony\Component\Filesystem\Filesystem;
use Symfony\Component\Filesystem\Exception\IOExceptionInterface;

/**
 * Class for encrypting and decrypting with the defuse library
 *
 * @author Michael de Groot <specamps@gmail.com>
 */

class DefuseEncryptor implements EncryptorInterface
{
    private $fs;
    private $encryptionKey;
    private $keyFile;

    /**
     * {@inheritdoc}
     */
    public function __construct(string $keyFile)
    {
        $this->encryptionKey = null;
        $this->keyFile       = $keyFile;
        $this->fs            = new Filesystem();
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data)
    {
        return \Defuse\Crypto\Crypto::encryptWithPassword($data, $this->getKey());
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($data)
    {
        return \Defuse\Crypto\Crypto::decryptWithPassword($data, $this->getKey());
    }

    private function getKey()
    {
        if ($this->encryptionKey === null) {
            if ($this->fs->exists($this->keyFile)) {
                $this->encryptionKey = file_get_contents($this->keyFile);
            } else {
                $string = random_bytes(255);
                $this->encryptionKey = bin2hex($string);
                $this->fs->dumpFile($this->keyFile, $this->encryptionKey);
            }
        }

        return $this->encryptionKey;
    }
}
