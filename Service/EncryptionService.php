<?php
/**
 * Company: studio.201 software GmbH
 * User: tk@studio201.de
 * Date: 2019-10-24
 * Time: 13:10
 */

namespace Studio201\DoctrineEncryptBundle\Service;

use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\Halite\KeyFactory;
use Symfony\Bundle\FrameworkBundle\Controller\Controller as BasisController;

/**
 * Class EncryptionService
 * @package Studio201\DoctrineEncryptBundle\Service
 */
class EncryptionService extends BasisController
{

    /**
     * @return \ParagonIE\Halite\EncryptionKeyPair
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    public function generateSignatureKeyPair()
    {
        $seal_keypair = KeyFactory::generateSignatureKeyPair();

        return [
            "publicKey" => KeyFactory::export($seal_keypair->getPublicKey()),
            "privateKey" => KeyFactory::export($seal_keypair->getSecretKey()),
        ];
    }

    /**
     * @param $secretKey
     * @param $message
     * @return string
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function signMessage($secretKey, $message)
    {
        $importedSecretKey = KeyFactory::importSignatureSecretKey($secretKey);

        return Crypto::sign($message, $importedSecretKey);
    }

    /**
     * @param $publicKey
     * @param $message
     * @return bool
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     * @throws \ParagonIE\Halite\Alerts\InvalidSignature
     * @throws \ParagonIE\Halite\Alerts\InvalidType
     */
    public function verifyMessage($publicKey, $message, $signature)
    {
        $importedPublicKey = KeyFactory::importSignaturePublicKey($publicKey);

        return Crypto::verify($message, $importedPublicKey, $signature);
    }

}
