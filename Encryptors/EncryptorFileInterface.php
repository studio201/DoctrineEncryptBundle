<?php

namespace Studio201\DoctrineEncryptBundle\Encryptors;

/**
 * Encryptor interface for encryptors
 *
 * @author David Muench
 */
interface EncryptorFileInterface
{

    /**
     * @param string $keyFile Path where to find and store the keyfile
     */
    public function __construct(string $keyFile);


    public function encryptFile($inputFile, $outputFile);


    public function decryptFile($inputFile, $outputFile);
}
