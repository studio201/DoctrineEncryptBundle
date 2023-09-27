<?php
/**
 * Company: studio.201 software GmbH
 * User: tk@studio201.de
 * Date: 2019-10-24
 * Time: 13:10
 */

namespace Studio201\DoctrineEncryptBundle\Service;

use ParagonIE\Halite\Asymmetric\Crypto;
use ParagonIE\Halite\HiddenString;
use ParagonIE\Halite\KeyFactory;
use Symfony\Bundle\FrameworkBundle\Controller\Controller as BasisController;

/**
 * Class EncryptionService
 * @package Studio201\DoctrineEncryptBundle\Service
 */
class EncryptionService extends BasisController
{

    /**
     * @return array{publicKey: \ParagonIE\HiddenString\HiddenString, privateKey: \ParagonIE\HiddenString\HiddenString}
     * @throws \ParagonIE\Halite\Alerts\InvalidKey
     */
    public function generateSignatureKeyPair(): array
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
    public function signMessage($secretKey, string $message): string
    {
        if (is_string($secretKey)) {
            $secretKey = new HiddenString($secretKey);
        }
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
    public function verifyMessage(\ParagonIE\HiddenString\HiddenString $publicKey, string $message, string $signature): bool
    {
        $importedPublicKey = KeyFactory::importSignaturePublicKey($publicKey);

        return Crypto::verify($message, $importedPublicKey, $signature);
    }

}
