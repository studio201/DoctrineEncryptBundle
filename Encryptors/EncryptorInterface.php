<?php

namespace Studio201\DoctrineEncryptBundle\Encryptors;

/**
 * Encryptor interface for encryptors
 *
 * @author Victor Melnik <melnikvictorl@gmail.com>
 */
interface EncryptorInterface
{

    /**
     * @param string $keyFile Path where to find and store the keyfile
     */
    public function __construct(string $keyFile);

    /**
     * @param string $data Plain text to encrypt
     * @return string Encrypted text
     */
    public function encrypt($data);

    /**
     * @param string $data Encrypted text
     * @return string Plain text
     */
    public function decrypt($data);
}
