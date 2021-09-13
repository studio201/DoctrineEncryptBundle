<?php

namespace Studio201\DoctrineEncryptBundle\Encryptors;

use ParagonIE\Halite\Alerts\InvalidMessage;
use \ParagonIE\Halite\HiddenString;
use \ParagonIE\Halite\EncryptionKey;
use \ParagonIE\Halite\KeyFactory;
use \ParagonIE\Halite\Symmetric\Crypto;

/**
 * Class for encrypting and decrypting with the halite library
 *
 * @author Michael de Groot <specamps@gmail.com>
 */

class HaliteEncryptor implements EncryptorInterface, EncryptorFileInterface
{
    private $encryptionKey;
    private $keyFile;

    /**
     * {@inheritdoc}
     */
    public function __construct(string $keyFile)
    {
        $this->encryptionKey = null;
        $this->keyFile = $keyFile;
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data)
    {
        return \ParagonIE\Halite\Symmetric\Crypto::encrypt(new HiddenString($data), $this->getKey());
    }


    /**
     * {@inheritdoc}
     */
    public function decrypt($data)
    {
        if(null == $data) {
            return $data;
        }
        try{
            return \ParagonIE\Halite\Symmetric\Crypto::decrypt($data, $this->getKey());
        }
        catch(InvalidMessage $e){

        }
        return $data;
    }


    /**
     * {@inheritdoc}
     */
    public function encryptFile($inputFile, $outputFile)
    {
        return \ParagonIE\Halite\File::encrypt($inputFile, $outputFile, $this->getKey());
    }

     /**
     * Example USAGE
       $this->getEncryptorService()->decryptFile($encryptedFilePath, $decryptedFilePath);
        $response = new BinaryFileResponse($decryptedFilePath);
        $response->deleteFileAfterSend(true);  // important, delete decryptedFile after sending
        $response->setContentDisposition(ResponseHeaderBag::DISPOSITION_ATTACHMENT, $document->getName());
        return $response;
     */
    public function decryptFile($inputFile, $outputFile)
    {
        return \ParagonIE\Halite\File::decrypt($inputFile, $outputFile, $this->getKey());
    }



    private function getKey()
    {
        if ($this->encryptionKey === null) {
            try {
                $this->encryptionKey = \ParagonIE\Halite\KeyFactory::loadEncryptionKey($this->keyFile);
            } catch (\ParagonIE\Halite\Alerts\CannotPerformOperation $e) {
                $this->encryptionKey = KeyFactory::generateEncryptionKey();
                \ParagonIE\Halite\KeyFactory::save($this->encryptionKey, $this->keyFile);
            }
        }

        return $this->encryptionKey;
    }
}
