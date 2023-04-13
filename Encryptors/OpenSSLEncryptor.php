<?php

namespace Studio201\DoctrineEncryptBundle\Encryptors;

/**
 * Class for encrypting and decrypting with OpenSSL library.
 *
 * @see https://synet.sk/blog/php/320-benchmarking-symmetric-cyphers-openssl-vs-mcrypt-in-php
 */
class OpenSSLEncryptor implements EncryptorInterface
{
    const ENCRYPTION_MARKER = '<ENCv2>';
    private const METHOD = 'AES-256-CBC';



    private const OPTIONS = 0; //OPENSSL_RAW_DATA || OPENSSL_ZERO_PADDING;

    private const PASSWORD = 'qq4fqFx$rq3r32';

    private $iv;
    private $password = "";
    private $keyFile;



    public function __construct(string $keyFile)
    {
        $this->keyFile = $keyFile;
        $this->password = $this->getKey();
        $length = openssl_cipher_iv_length(self::METHOD);
        $this->iv = substr(md5($this->password), 0, $length);
    }

    /**
     * {@inheritdoc}
     */
    public function encrypt($data) {
        return openssl_encrypt($data, self::METHOD, $this->password, self::OPTIONS, $this->iv);
    }

    /**
     * {@inheritdoc}
     */
    public function decrypt($data) { //TODO data = null
        return openssl_decrypt($data, self::METHOD, $this->password, self::OPTIONS, $this->iv);
    }

    /**
     * {@inheritdoc}
     */
    public function encryptFile($inputFile, $outputFile)
    {

        return file_put_contents($outputFile, $this->encrypt(file_get_contents($inputFile)));
    }

    /**
     * @param $inputFile
     * @param $outputFile
     * @return bool
     */
    public function decryptFile($inputFile, $outputFile)
    {
        return file_put_contents($outputFile, $this->decrypt(file_get_contents($inputFile)));
    }

    private function getKey()
    {
        if($this->keyFile == null || $this->keyFile==""){
            throwException("Keyfile not set");
        }

        if (empty($this->password)) {

            if(file_exists($this->keyFile) == false){
                $bytes = openssl_random_pseudo_bytes(32);
                $pwd = bin2hex($bytes);
                file_put_contents($this->keyFile, $pwd);
                $this->password = $pwd;
            }
            else{
                $this->password =  file_get_contents($this->keyFile);
            }


        }

        return $this->password;
    }

}
