<?php
/**
 * Company: studio.201 software GmbH
 * User: tk@studio201.de
 * Date: 03.05.16
 * Time: 16:36
 */

namespace Studio201\DoctrineEncryptBundle\Encryptors;

use Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface;


/**
 * Class CoreEncryptor
 * encryptiopn/decryption of entities with (at)Encrypted annotation
 *
 * @package StudioMedPlus\CoreBundle\Security\Encryption
 */
class OldCoreEncryptor implements EncryptorInterface
{

    /**
     * @var string ALGORITYM Zu verwendender Verschlüsselungs-(Cipher)-Algorithmus
     *
     * MCRYPT_3DES
     * MCRYPT_ARCFOUR_IV (libmcrypt > 2.4.x only)
     * MCRYPT_ARCFOUR (libmcrypt > 2.4.x only)
     * MCRYPT_BLOWFISH
     * MCRYPT_CAST_128
     * MCRYPT_CAST_256
     * MCRYPT_CRYPT
     * MCRYPT_DES
     * MCRYPT_DES_COMPAT (libmcrypt 2.2.x only)
     * MCRYPT_ENIGMA (libmcrypt > 2.4.x only, alias for MCRYPT_CRYPT)
     * MCRYPT_GOST
     * MCRYPT_IDEA (non-free)
     * MCRYPT_LOKI97 (libmcrypt > 2.4.x only)
     * MCRYPT_MARS (libmcrypt > 2.4.x only, non-free)
     * MCRYPT_PANAMA (libmcrypt > 2.4.x only)
     * MCRYPT_RIJNDAEL_128 (libmcrypt > 2.4.x only)
     * MCRYPT_RIJNDAEL_192 (libmcrypt > 2.4.x only)
     * MCRYPT_RIJNDAEL_256 (libmcrypt > 2.4.x only)
     * MCRYPT_RC2
     * MCRYPT_RC4 (libmcrypt 2.2.x only)
     * MCRYPT_RC6 (libmcrypt > 2.4.x only)
     * MCRYPT_RC6_128 (libmcrypt 2.2.x only)
     * MCRYPT_RC6_192 (libmcrypt 2.2.x only)
     * MCRYPT_RC6_256 (libmcrypt 2.2.x only)
     * MCRYPT_SAFER64
     * MCRYPT_SAFER128
     * MCRYPT_SAFERPLUS (libmcrypt > 2.4.x only)
     * MCRYPT_SERPENT(libmcrypt > 2.4.x only)
     * MCRYPT_SERPENT_128 (libmcrypt 2.2.x only)
     * MCRYPT_SERPENT_192 (libmcrypt 2.2.x only)
     * MCRYPT_SERPENT_256 (libmcrypt 2.2.x only)
     * MCRYPT_SKIPJACK (libmcrypt > 2.4.x only)
     * MCRYPT_TEAN (libmcrypt 2.2.x only)
     * MCRYPT_THREEWAY
     * MCRYPT_TRIPLEDES (libmcrypt > 2.4.x only)
     * MCRYPT_TWOFISH (for older mcrypt 2.x versions, or mcrypt > 2.4.x )
     * MCRYPT_TWOFISH128 (TWOFISHxxx are available in newer 2.x versions, but not in the 2.4.x versions)
     * MCRYPT_TWOFISH192
     * MCRYPT_TWOFISH256
     * MCRYPT_WAKE (libmcrypt > 2.4.x only)
     * MCRYPT_XTEA (libmcrypt > 2.4.x only)
     * //TODO: replace after migration to php7.2
     */
    const ALGORITYM = "rijndael-128";
    /**
     * @var string MODE zu verwendender CBC Mode
     *
     * MCRYPT_MODE_ECB (electronic codebook) is suitable for random data, such as encrypting other keys.
     *                  Since data there is short and random, the disadvantages of ECB have a favorable negative effect.
     * MCRYPT_MODE_CBC (cipher block chaining) is especially suitable for encrypting files where the
     *                  security is increased over ECB significantly.
     * MCRYPT_MODE_CFB (cipher feedback) is the best mode for encrypting byte streams where
     *                  single bytes must be encrypted.
     * MCRYPT_MODE_OFB (output feedback, in 8bit) is comparable to CFB, but can be used in
     *                  applications where error propagation cannot be tolerated. It's insecure (because it operates
     *                  in 8bit mode) so it is not recommended to use it.
     * MCRYPT_MODE_NOFB (output feedback, in nbit) is comparable to OFB, but more secure because it operates on
     *                  the block size of the algorithm.
     * MCRYPT_MODE_STREAM is an extra mode to include some stream algorithms like "WAKE" or "RC4".
     */
    const MODE = "cbc";//MCRYPT_MODE_CBC;
    /**
     * @var string IV_MODE zu verwendender Initialisierungs-Vector Mode
     *
     * MCRYPT_DEV_RANDOM (read data from /dev/random) - Linux
     * MCRYPT_DEV_URANDOM (read data from /dev/random) - Linux
     * MCRYPT_RAND (system random number generator) - Windows
     *
     */
    const IV_MODE = 2;//MCRYPT_RAND;
    /**
     * Secret key for aes algorythm
     * @var string
     */
    private $secretKey;

    /**
     * Initialization of encryptor
     * @param string $key
     */
    public function __construct(string $key)
    {
        $this->secretKey = $key;
    }

    /**
     * Generate new String based uppon MD5 with multiple length
     * @param $length
     * @return string
     */
    public static function generateMd5($length)
    {
        $max = ceil($length / 32);
        $random = '';
        for ($i = 0; $i < $max; $i++) {
            $random .= md5(microtime(true).mt_rand(10000, 90000));
        }

        return substr($random, 0, $length);
    }

    /**
     * Generate new String based uppon SHA-1 with multiple length
     * @param $length
     * @return string
     */
    public static function generateSha1($length)
    {
        $max = ceil($length / 40);
        $random = '';
        for ($i = 0; $i < $max; $i++) {
            $random .= sha1(microtime(true).mt_rand(10000, 90000));
        }

        return substr($random, 0, $length);
    }

    /**
     * Implementation of EncryptorInterface encrypt method
     * @param string $string
     * @return string
     */
    public function encrypt($string)
    {
        $key = $this->secretKey;
        //using hexadecimal
        $key = pack('H*', (string)$key);

        //$keySize = self::getKeySize($key);
        $iv = self::getIv();
        $cipherText = self::getCipherText($string, $key, $iv);

        //prepend the IV for it to be available for decryption
        $cipherText = $iv.$cipherText;

        return self::encode($cipherText);
    }

    /**
     * key size use either 16, 24 or 32 byte keys for AES-128, 192 and 256 respectively
     * @param $key string
     * @return int
     */
    /*private static function getKeySize($key)
    {
        return strlen($key);
    }*/

    /**
     * create a random IV to use with CBC encoding
     * @return string
     */
    private static function getIv()
    {
        $ivSize = mcrypt_get_iv_size(self::ALGORITYM, self::MODE);

        return mcrypt_create_iv($ivSize, self::IV_MODE);
    }

    /**
     * creates a cipher text compatible with AES (Rijndael block size = 128)
     * to keep the text confidential
     * only suitable for encoded input that never ends with value 00h
     * (because of default zero padding)
     * @param $plainText
     * @param $key
     * @param $iv
     * @return string
     */
    private static function getCipherText($plainText, $key, $iv)
    {
        return mcrypt_encrypt(self::ALGORITYM, $key, $plainText, self::MODE, $iv);
    }

    /**
     * encode the resulting cipher text so it can be represented by a string
     * @param $string
     * @return string
     */
    private static function encode($string)
    {
        return base64_encode($string);
    }

    /**
     * Implementation of EncryptorInterface decrypt method
     * @param string $string
     * @return string
     */
    public function decrypt($string)
    {
        $key = $this->secretKey;
        //using hexadecimal
        $key = pack('H*', (string)$key);

        $cipherText = self::decode($string);

        $ivSize = self::getIvSize();
        //retrieves the IV, iv_size should be created using mcrypt_get_iv_size()
        $iv = substr($cipherText, 0, $ivSize);

        //retrieves the cipher text (everything except the $iv_size in the front)
        $cipherText = substr($cipherText, $ivSize);
        $decrypted = self::getPlainText($cipherText, $key, $iv);
        $decrypted = rtrim($decrypted, "\0\4");

        return $decrypted;
    }

    /**
     * decode the resulting cipher text so it can be represented by a string
     * @param $string
     * @return string
     */
    private static function decode($string)
    {
        return base64_decode($string);
    }

    /**
     *
     * @return int
     */
    private static function getIvSize()
    {
        return mcrypt_get_iv_size(self::ALGORITYM, self::MODE);
    }

    /**
     * may remove 00h valued characters from end of plain text
     * @param $cipherText
     * @param $key
     * @param $iv
     * @return string
     */
    private static function getPlainText($cipherText, $key, $iv)
    {
        return mcrypt_decrypt(self::ALGORITYM, $key, $cipherText, self::MODE, $iv);
    }
}
