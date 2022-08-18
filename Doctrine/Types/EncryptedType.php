<?php
/**
 * Company: studio.201 software GmbH
 * User:    mludewig
 * Date:    24.06.2021
 * Time:    13:39
 */

namespace Studio201\DoctrineEncryptBundle\Doctrine\Types;

use Doctrine\DBAL\Platforms\AbstractPlatform;
use Doctrine\DBAL\Types\Type;
use Doctrine\DBAL\Types\Types;
use Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface;
use Studio201\DoctrineEncryptBundle\EventListener\Crypter;
use Studio201\DoctrineEncryptBundle\Subscribers\DoctrineEncryptSubscriber;

/**
 * Class EncryptedType
 * @package Studio201\DoctrineEncryptBundle\Doctrine\Types
 */
class EncryptedType extends Type
{
    const ENCRYPTED = 'encrypted';

    /**
     * @return string
     */
    public function getName(): string
    {
        return self::ENCRYPTED;
    }

    /**
     * @param mixed $value
     * @param AbstractPlatform $platform
     * @return string
     */
    public function convertToPHPValue($value, AbstractPlatform $platform): string
    {
        if (null == $value || $value === '') {
            return '';
        }
        $crypter = $this->getCrypter($platform);
        if(strpos($value, $crypter::ENCRYPTION_MARKER) > 0){
            $value =   substr($value, 0, -strlen($crypter::ENCRYPTION_MARKER));
            return $crypter->decrypt($value);
        }
        else{
            return $value;
        }


    }

    /**
     * @param mixed $value
     * @param AbstractPlatform $platform
     * @return string
     */
    public function convertToDatabaseValue($value, AbstractPlatform $platform): string
    {
        if (null == $value || $value === '') {
            return '';
        }

        $crypter = $this->getCrypter($platform);

        return $crypter->encrypt($value).$crypter::ENCRYPTION_MARKER;
    }

    /**
     * @param AbstractPlatform $platform
     * @return EncryptorInterface
     */
    private function getCrypter(AbstractPlatform $platform): EncryptorInterface
    {
        /** @var array $listCrypterListener */
        $listCrypterListener = $platform->getEventManager()->getListeners('crypter');
        /** @var Crypter $crypterListener */
        $crypterListener = array_shift($listCrypterListener);

        return $crypterListener->getCrypter();
    }

    /**
     * @param array $fieldDeclaration
     * @param AbstractPlatform $platform
     * @return string
     */
    public function getSQLDeclaration(array $fieldDeclaration, AbstractPlatform $platform)
    {
        $fieldDeclaration["type"] = Types::TEXT;
        return $platform->getClobTypeDeclarationSQL($fieldDeclaration);
    }
}
