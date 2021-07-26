<?php
/**
 * Company: studio.201 software GmbH
 * User:    mludewig
 * Date:    24.06.2021
 * Time:    13:56
 */
namespace Studio201\DoctrineEncryptBundle\EventListener;

use Doctrine\Common\EventSubscriber;
use Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface;

/**
 * Class Crypter
 * @package Studio201\DoctrineEncryptBundle\EventListener
 */
class Crypter
{
    protected $crypter;

    /**
     * Crypter constructor.
     * @param EncryptorInterface $crypter
     */
    public function __construct(EncryptorInterface $crypter)
    {
        $this->crypter = $crypter;
    }

    /**
     *
     */
    public function getCrypter()
    {
        return $this->crypter;
    }
}
