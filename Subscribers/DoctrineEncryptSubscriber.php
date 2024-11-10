<?php

namespace Studio201\DoctrineEncryptBundle\Subscribers;

use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\Collections\ArrayCollection;
use Doctrine\Common\EventSubscriber;
use Doctrine\Common\Util\ClassUtils;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Doctrine\ORM\Event\PreFlushEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Events;
use Doctrine\ORM\UnitOfWork;
use ParagonIE\Halite\Alerts\HaliteAlert;
use ParagonIE\Halite\HiddenString;
use ReflectionClass;
use ReflectionProperty;
use Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface;
use Symfony\Component\PropertyAccess\PropertyAccess;

/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
#[AsDoctrineListener]
class DoctrineEncryptSubscriber implements EventSubscriber
{
    /**
     * Appended to end of encrypted value
     */
    const ENCRYPTION_MARKER = '<ENCv2>';

    const ENCRYPTION_MARKER_OLD = '<ENCv1>';

    /**
     * Encryptor interface namespace
     */
    const ENCRYPTOR_INTERFACE_NS = 'Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface';

    /**
     * Encrypted annotation full name
     */
    const ENCRYPTED_ANN_NAME = 'Studio201\DoctrineEncryptBundle\Configuration\Encrypted';

    /**
     * Encryptor
     */
    private \Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface|null|string $encryptor = null;

    /**
     * Encryptor
     */
    private ?\Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface $oldEncryptor = null;

    /**
     * Annotation reader
     */
    private \Doctrine\Common\Annotations\Reader $annReader;

    /**
     * Secret key
     * @var string
     */
    private $secretKey;

    /**
     * Used for restoring the encryptor after changing it
     * @var string
     */
    private \Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface $restoreEncryptor;

    /**
     * User for storing all entities we decrypted after flushing, so we know which ones to re-encrypt
     */
    private \Doctrine\Common\Collections\ArrayCollection $decryptedEntities;

    /**
     * Count amount of decrypted values in this service
     * @var integer
     */
    public $decryptCounter = 0;

    /**
     * Count amount of encrypted values in this service
     * @var integer
     */
    public $encryptCounter = 0;

    /**
     * @var
     */
    protected $logger;

    /**
     * @var
     */
    protected $entityManager;

    protected bool $convertFromOld = false;

    /**
     * Initialization of subscriber
     *
     * @param Reader $annReader
     * @param string $encryptorClass The encryptor class.  This can be empty if a service is being provided.
     * @param string $secretKey The secret key.
     * @param EncryptorInterface|NULL $service (Optional)  An EncryptorInterface.
     *
     * This allows for the use of dependency injection for the encrypters.
     */
    public function __construct( EncryptorInterface $encryptor, $oldSecretKey = null)
    {
        //$this->annReader = $annReader;
        $this->encryptor = $encryptor;
        $this->restoreEncryptor = $this->encryptor;
        $this->secretKey = $oldSecretKey;
        $this->decryptedEntities = new ArrayCollection();
    }

    /**
     * Get the current encryptor
     *
     * @return EncryptorInterface returns the encryptor class or null
     */
    public function getEncryptor()
    {
        return $this->encryptor;
    }

    /**
     * Change the encryptor
     * @param [type] $[name] [<description>]
     * @param EncryptorInterface $encryptorClass
     */
    public function setEncryptor(EncryptorInterface $encryptorClass = null): void
    {
        $this->encryptor = $encryptorClass;
    }

    /**
     * Restore encryptor set in config
     */
    public function restoreEncryptor(): void
    {
        $this->encryptor = $this->restoreEncryptor;
    }

    /**
     * @return EncryptorInterface
     */
    public function getOldEncryptor()
    {
        return $this->oldEncryptor;
    }

    /**
     * @param EncryptorInterface $oldEncryptorClass
     */
    public function setOldEncryptor($oldEncryptorClass): void
    {
        if (!is_null($oldEncryptorClass) && ($oldEncryptorClass instanceof EncryptorInterface) == false) {
            $this->oldEncryptor = $this->encryptorFactory($oldEncryptorClass, $this->secretKey);

            return;
        }

        $this->oldEncryptor = $oldEncryptorClass;
    }

    /**
     * @param mixed $logger
     */
    public function setLogger($logger): void
    {
        $this->logger = $logger;
    }

    /**
     * @param mixed $entityManager
     */
    public function setEntityManager($entityManager): void
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Listen a postUpdate lifecycle event.
     * Decrypt entities property's values when post updated.
     *
     * So for example after form submit the preUpdate encrypted the entity
     * We have to decrypt them before showing them again.
     *
     * @param LifecycleEventArgs $args
     */
    public function postUpdate(LifecycleEventArgs $args): void
    {

        $entity = $args->getObject();
        $this->processFields($entity, false);

    }

    /**
     * Listen a preUpdate lifecycle event.
     * Encrypt entities property's values on preUpdate, so they will be stored encrypted
     *
     * @param PreUpdateEventArgs $args
     */
    public function preUpdate(PreUpdateEventArgs $args): void
    {
        $entity = $args->getObject();
        $this->processFields($entity);
    }

    /**
     * Listen a prePersist lifecycle event.
     * @param LifecycleEventArgs $args
     */
    public function prePersist(LifecycleEventArgs $args): void
    {

        $entity = $args->getObject();
        $this->processFields($entity);
    }

    /**
     * Listen a postLoad lifecycle event.
     * Decrypt entities property's values when loaded into the entity manger
     *
     * @param LifecycleEventArgs $args
     */
    public function postLoad(LifecycleEventArgs $args): void
    {

        //Get entity and process fields
        $entity = $args->getObject();
        $this->processFields($entity, false);

    }

    /**
     * Listen to preflush event
     * Encrypt entities that are inserted into the database
     *
     * @param PreFlushEventArgs $preFlushEventArgs
     */
    public function preFlush(PreFlushEventArgs $preFlushEventArgs): void
    {
        $unitOfWork = $preFlushEventArgs->getObjectManager()->getUnitOfWork();
        foreach ($unitOfWork->getScheduledEntityInsertions() as $entity) {
            $this->processFields($entity);
        }

        // Re-encrypt all previously decrypted entities
        foreach ($this->decryptedEntities as $entity) {
            $this->processFields($entity, true, $unitOfWork);
        }
    }

    /**
     * Listen to postFlush event
     * Decrypt entities that after inserted into the database
     *
     * @param PostFlushEventArgs $postFlushEventArgs
     */
    public function postFlush(PostFlushEventArgs $postFlushEventArgs): void
    {
        $unitOfWork = $postFlushEventArgs->getObjectManager()->getUnitOfWork();
        foreach ($unitOfWork->getIdentityMap() as $entityMap) {
            foreach ($entityMap as $entity) {
                $this->processFields($entity, false);
            }
        }
    }

    /**
     * Realization of EventSubscriber interface method.
     *
     * @return array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents(): array
    {
        return array(
            Events::postUpdate,
            Events::preUpdate,
            Events::postLoad,
            Events::preFlush,
            Events::postFlush,
        );
    }

    /**
     * Process (encrypt/decrypt) entities fields
     *
     * @param Object $entity doctrine entity
     * @param Boolean $isEncryptOperation If true - encrypt, false - decrypt entity
     * @param UnitOfWork|null $unitOfWork
     *
     * @throws \RuntimeException
     *
     * @return object|null
     */
    public function processFields($entity, $isEncryptOperation = true, $unitOfWork = null)
    {

        if ($this->encryptor instanceof \Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface) {
            // Check which operation to be used
            $encryptorMethod = $isEncryptOperation ? 'encrypt' : 'decrypt';

            // Get the real class, we don't want to use the proxy classes
            if (strstr(get_class($entity), 'Proxies')) {
                $realClass = ClassUtils::getClass($entity);
            } else {
                $realClass = get_class($entity);
            }

            // Get ReflectionClass of our entity
            $reflectionClass = new ReflectionClass($realClass);
            $properties = $this->getClassProperties($realClass);

            // Foreach property in the reflection class
            foreach ($properties as $refProperty) {
               /* if ($this->annReader->getPropertyAnnotation($refProperty, 'Doctrine\ORM\Mapping\Embedded')) {
                    $this->handleEmbeddedAnnotation($entity, $refProperty, $isEncryptOperation);
                    continue;
                }*/

                /**
                 * If property is an normal value and contains the Encrypt tag, lets encrypt/decrypt that property
                 */
             /*   if ($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)) {

                    $pac = PropertyAccess::createPropertyAccessor();
                    $value = $pac->getValue($entity, $refProperty->getName());
                    if ($encryptorMethod == 'decrypt') {

                        if (!is_null($value) and !empty($value)) {
                            $currentPropValue = $value;

                            if (substr($value, -strlen(self::ENCRYPTION_MARKER)) == self::ENCRYPTION_MARKER) {
                                $this->decryptCounter++;
                                $this->decryptedEntities->add($entity);
                                $currentPropValue = $this->encryptor->decrypt(substr($value, 0, -strlen(self::ENCRYPTION_MARKER)));

                                $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                                $name = $refProperty->getName();
                            } elseif (substr($value, -strlen(self::ENCRYPTION_MARKER_OLD)) == self::ENCRYPTION_MARKER_OLD) {
                                $this->decryptCounter++;
                                $currentPropValue = $this->oldEncryptor->decrypt(substr($value, 0, -strlen(self::ENCRYPTION_MARKER_OLD)));

                                $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                                $name = $refProperty->getName();
                            } else {

                                try {
                                    if ($this->convertFromOld == true && $this->oldEncryptor != null) {
                                        $currentPropValue = $this->oldEncryptor->decrypt($value);

                                    }
                                } catch (\Exception $ex) {
                                    $currentPropValue = $value;
                                }
                                $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                            }

                        }
                    } else {
                        if (!is_null($value) and !empty($value)) {
                            if (substr($value, -strlen(self::ENCRYPTION_MARKER)) != self::ENCRYPTION_MARKER) {
                                //$this->encryptCounter++;
                                //$currentPropValue = $this->encryptor->encrypt($value).self::ENCRYPTION_MARKER;
                                // Check if original unencrypted differs from new unencrypted value
                                $currentPropValue = $this->encryptor->encrypt($value).self::ENCRYPTION_MARKER;
                                $encryptionChanged = $this->hasEncryptedFieldsChanged($unitOfWork, $entity, $refProperty);
                                if ($unitOfWork !== null && $encryptionChanged == false) {
                                    $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                                    $originalData = $unitOfWork->getOriginalEntityData($entity);

                                    //Revert to original encrypted value if both unencrypted values are the same
                                    $pac->setValue($entity, $refProperty->getName(), $originalData[$refProperty->getName()]);
                                } else {
                                    $this->encryptCounter++;
                                    $currentPropValue = $this->encryptor->encrypt($value).self::ENCRYPTION_MARKER;
                                    $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                                }

                            } 


                        }
                    }
                }*/
            }

            return $entity;
        }

        return $entity;
    }

    /**
     * Method that check if current encrypt values match with old ones
     * @param UnitOfWork $unitOfWork
     * @param $entity
     * @param ReflectionProperty $refProperty
     * @return bool
     */
    private function hasEncryptedFieldsChanged($unitOfWork, object|array $entity, ReflectionProperty $refProperty): bool
    {
        if ($unitOfWork == null) {
            return true;
        }
        $originalData = $unitOfWork->getOriginalEntityData($entity);

        //Get old value
        try {
            if (!isset($originalData[$refProperty->getName()])) {
                return true;
            }

            // Always encrypt when original-value is not encrypted
            if (substr($originalData[$refProperty->getName()], -strlen(self::ENCRYPTION_MARKER)) !== self::ENCRYPTION_MARKER) {
                return true;
            }

            $oldValue = $this->encryptor->decrypt(substr($originalData[$refProperty->getName()], 0, -strlen(self::ENCRYPTION_MARKER)));
            if ($oldValue instanceof HiddenString) {
                $oldValue = $oldValue->getString();
            }
        } catch (HaliteAlert $e) {
            $oldValue = $originalData[$refProperty->getName()];
        } catch (\TypeError $e) {
            $oldValue = $originalData[$refProperty->getName()];
        } /*catch (CryptoException $e ){
            $oldValue=$originalData[$refProperty->getName()];
        }*/

        //Get new value
        $pac = PropertyAccess::createPropertyAccessor();
        $newEntityValue = $pac->getValue($entity, $refProperty->getName());

        if (substr($newEntityValue, -strlen(self::ENCRYPTION_MARKER)) !== self::ENCRYPTION_MARKER) {
            $newValue = $newEntityValue;
        } else {
            try {
                $newValue = $this->encryptor->decrypt(substr($newEntityValue, 0, -strlen(self::ENCRYPTION_MARKER)));
            } catch (HaliteAlert $e) {
                $newValue = $newEntityValue;
            } catch (\TypeError $e) {
                $newValue = $newEntityValue;
            } /*catch (CryptoException $e ){
                $newValue = $newEntityValue;
            }*/
        }

        return $newValue != $oldValue;
    }

    /**
     * @param $entity
     * @param ReflectionProperty $embeddedProperty
     * @param bool $isEncryptOperation
     */
    private function handleEmbeddedAnnotation(object|array $entity, ReflectionProperty $embeddedProperty, $isEncryptOperation = true): void
    {
        $propName = $embeddedProperty->getName();

        $pac = PropertyAccess::createPropertyAccessor();

        $embeddedEntity = $pac->getValue($entity, $propName);

        if ($embeddedEntity) {
            $this->processFields($embeddedEntity, $isEncryptOperation);
        }
    }

    /**
     * Recursive function to get an associative array of class properties
     * including inherited ones from extended classes
     *
     * @param string $className Class name
     *
     * @return array
     */
    private function getClassProperties($className)
    {
        $reflectionClass = new ReflectionClass($className);
        $properties = $reflectionClass->getProperties();
        $propertiesArray = array();

        foreach ($properties as $property) {
            $propertyName = $property->getName();
            $propertiesArray[$propertyName] = $property;
        }

        if ($parentClass = $reflectionClass->getParentClass()) {
            $parentPropertiesArray = $this->getClassProperties($parentClass->getName());
            if (count($parentPropertiesArray) > 0) {
                $propertiesArray = array_merge($parentPropertiesArray, $propertiesArray);
            }
        }

        return $propertiesArray;
    }

    /**
     * Encryptor factory. Checks and create needed encryptor
     *
     * @param string $classFullName Encryptor namespace and name
     * @param string $secretKey Secret key for encryptor
     *
     * @return EncryptorInterface
     * @throws \RuntimeException
     */
    private function encryptorFactory($classFullName, $secretKey)
    {
        $refClass = new \ReflectionClass($classFullName);

        //if ($refClass->implementsInterface(self::ENCRYPTOR_INTERFACE_NS)) {
        return new $classFullName($secretKey);
        //} else {
        //    throw new \RuntimeException('Encryptor must implements interface EncryptorInterface');
        // }
    }
}
