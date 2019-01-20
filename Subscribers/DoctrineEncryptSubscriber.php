<?php

namespace Studio201\DoctrineEncryptBundle\Subscribers;

use Doctrine\Common\Annotations\Reader;
use Doctrine\Common\EventSubscriber;
use Doctrine\Common\Util\ClassUtils;
use Doctrine\ORM\Event\LifecycleEventArgs;
use Doctrine\ORM\Event\PostFlushEventArgs;
use Doctrine\ORM\Event\PreFlushEventArgs;
use Doctrine\ORM\Event\PreUpdateEventArgs;
use Doctrine\ORM\Events;
use ReflectionClass;
use ReflectionProperty;
use Studio201\DoctrineEncryptBundle\Encryptors\EncryptorInterface;
use Symfony\Component\PropertyAccess\PropertyAccess;

/**
 * Doctrine event subscriber which encrypt/decrypt entities
 */
class DoctrineEncryptSubscriber implements EventSubscriber
{
    /**
     * Appended to end of encrypted value
     */
    const ENCRYPTION_MARKER = '<ENC>';

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
     * @var EncryptorInterface
     */
    private $encryptor;

    /**
     * Encryptor
     * @var EncryptorInterface
     */
    private $oldEncryptor;

    /**
     * Annotation reader
     * @var \Doctrine\Common\Annotations\Reader
     */
    private $annReader;

    /**
     * Secret key
     * @var string
     */
    private $secretKey;

    /**
     * Used for restoring the encryptor after changing it
     * @var string
     */
    private $restoreEncryptor;

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
    public function __construct(Reader $annReader, $encryptorClass, $secretKey, EncryptorInterface $service = null)
    {
        $this->annReader = $annReader;
        $this->secretKey = $secretKey;

        if ($service instanceof EncryptorInterface) {
            $this->encryptor = $service;
        } else {
            $this->encryptor = $this->encryptorFactory($encryptorClass, $secretKey);
        }

        $this->restoreEncryptor = $this->encryptor;
    }

    /**
     * Get the current encryptor
     */
    public function getEncryptor()
    {
        if (!empty($this->encryptor)) {
            return get_class($this->encryptor);
        } else {
            return null;
        }
    }

    /**
     * Change the encryptor
     *
     * @param $encryptorClass
     */
    public function setEncryptor($encryptorClass)
    {

        if (!is_null($encryptorClass)) {
            $this->encryptor = $this->encryptorFactory($encryptorClass, $this->secretKey);

            return;
        }

        $this->encryptor = null;
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
    public function setOldEncryptor($oldEncryptorClass)
    {
        if (!is_null($oldEncryptorClass)) {
            $this->oldEncryptor = $this->encryptorFactory($oldEncryptorClass, $this->secretKey);

            return;
        }

        $this->oldEncryptor = null;
    }

    /**
     * @param mixed $logger
     */
    public function setLogger($logger)
    {
        $this->logger = $logger;
    }

    /**
     * @param mixed $entityManager
     */
    public function setEntityManager($entityManager)
    {
        $this->entityManager = $entityManager;
    }

    /**
     * Restore encryptor set in config
     */
    public function restoreEncryptor()
    {
        $this->encryptor = $this->restoreEncryptor;
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
    public function postUpdate(LifecycleEventArgs $args)
    {

        $entity = $args->getEntity();
        $this->processFields($entity, false);

    }

    /**
     * Listen a preUpdate lifecycle event.
     * Encrypt entities property's values on preUpdate, so they will be stored encrypted
     *
     * @param PreUpdateEventArgs $args
     */
    public function preUpdate(PreUpdateEventArgs $args)
    {
        $entity = $args->getEntity();
        $this->processFields($entity);
    }

    /**
     * Listen a prePersist lifecycle event.
     * @param LifecycleEventArgs $args
     */
    public function prePersist(LifecycleEventArgs $args)
    {

        $entity = $args->getEntity();
        $this->processFields($entity);
    }

    /**
     * Listen a postLoad lifecycle event.
     * Decrypt entities property's values when loaded into the entity manger
     *
     * @param LifecycleEventArgs $args
     */
    public function postLoad(LifecycleEventArgs $args)
    {

        //Get entity and process fields
        $entity = $args->getEntity();
        $this->processFields($entity, false);

    }

    /**
     * Listen to preflush event
     * Encrypt entities that are inserted into the database
     *
     * @param PreFlushEventArgs $preFlushEventArgs
     */
    public function preFlush(PreFlushEventArgs $preFlushEventArgs)
    {
        $unitOfWork = $preFlushEventArgs->getEntityManager()->getUnitOfWork();
        foreach ($unitOfWork->getScheduledEntityInsertions() as $entity) {
            $this->processFields($entity);
        }
    }

    /**
     * Listen to postFlush event
     * Decrypt entities that after inserted into the database
     *
     * @param PostFlushEventArgs $postFlushEventArgs
     */
    public function postFlush(PostFlushEventArgs $postFlushEventArgs)
    {
        $unitOfWork = $postFlushEventArgs->getEntityManager()->getUnitOfWork();
        foreach ($unitOfWork->getIdentityMap() as $entityMap) {
            foreach ($entityMap as $entity) {
                $this->processFields($entity, false);
            }
        }
    }

    /**
     * Realization of EventSubscriber interface method.
     *
     * @return Array Return all events which this subscriber is listening
     */
    public function getSubscribedEvents()
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
     *
     * @throws \RuntimeException
     *
     * @return object|null
     */
    public function processFields($entity, $isEncryptOperation = true)
    {

        if (!empty($this->encryptor)) {
            //Check which operation to be used
            $encryptorMethod = $isEncryptOperation ? 'encrypt' : 'decrypt';

            //Get the real class, we don't want to use the proxy classes
            if (strstr(get_class($entity), 'Proxies')) {
                $realClass = ClassUtils::getClass($entity);
            } else {
                $realClass = get_class($entity);
            }

            //Get ReflectionClass of our entity
            $reflectionClass = new ReflectionClass($realClass);
            $properties = $this->getClassProperties($realClass);

            //Foreach property in the reflection class
            foreach ($properties as $refProperty) {
                if ($this->annReader->getPropertyAnnotation($refProperty, 'Doctrine\ORM\Mapping\Embedded')) {
                    $this->handleEmbeddedAnnotation($entity, $refProperty, $isEncryptOperation);
                    continue;
                }

                /**
                 * If property is an normal value and contains the Encrypt tag, lets encrypt/decrypt that property
                 */
                if ($this->annReader->getPropertyAnnotation($refProperty, self::ENCRYPTED_ANN_NAME)) {

                    $pac = PropertyAccess::createPropertyAccessor();
                    $value = $pac->getValue($entity, $refProperty->getName());
                    if ($encryptorMethod == 'decrypt') {

                        if (!is_null($value) and !empty($value)) {
                            $currentPropValue = $value;

                            if (substr($value, -strlen(self::ENCRYPTION_MARKER)) == self::ENCRYPTION_MARKER) {
                                        $this->decryptCounter++;
                                $currentPropValue = $this->encryptor->decrypt(substr($value, 0, -strlen(self::ENCRYPTION_MARKER)));
                               
                                 $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                                 $name = $refProperty->getName();
                                    } else {
                                        try {
                                    if ($this->oldEncryptor != null) {
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
                                        $this->encryptCounter++;
                                $currentPropValue = $this->encryptor->encrypt($value).self::ENCRYPTION_MARKER;
                                }
                           
                            $pac->setValue($entity, $refProperty->getName(), $currentPropValue);
                            
                            }
                        }
                    }
                }

            return $entity;
            }

            return $entity;
        }

 

    private function handleEmbeddedAnnotation($entity, $embeddedProperty, $isEncryptOperation = true)
    {
        $reflectionClass = new ReflectionClass($entity);
        $propName = $embeddedProperty->getName();
        $methodName = ucfirst($propName);

        if ($embeddedProperty->isPublic()) {
            $embeddedEntity = $embeddedProperty->getValue();
        } else {
            if ($reflectionClass->hasMethod($getter = 'get'.$methodName) && $reflectionClass->hasMethod($setter = 'set'.$methodName)) {

                //Get the information (value) of the property
                try {
                    $embeddedEntity = $entity->$getter();
                } catch (\Exception $e) {
                    $embeddedEntity = null;
                }
            }
        }
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
    function getClassProperties($className)
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
        if ($refClass->implementsInterface(self::ENCRYPTOR_INTERFACE_NS)) {
            return new $classFullName($secretKey);
        } else {
            throw new \RuntimeException('Encryptor must implements interface EncryptorInterface');
        }
    }
}
