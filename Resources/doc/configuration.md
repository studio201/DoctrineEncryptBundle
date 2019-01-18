# Configuration Reference

There is only 1 paramater in the configuration of the Doctrine encryption bundle.
This parameter is also optional.

* **encryptor_class** - Custom class for encrypting data
    * Encryptor class, [your own encryptor class](https://github.com/michaeldegroot/DoctrineEncryptBundle/blob/master/Resources/doc/custom_encryptor.md) will override encryptor paramater
    * Default: Halite

## yaml

``` yaml
studio201_doctrine_encrypt:
    encryptor_class: Halite # or Defuse
    secret_directory_path: '%kernel.project_dir%'   # Path where to store the keyfiles
```

## Important!

If you want to use Defuse, make sure to require it!

composer require "defuse/php-encryption ^2.0"

## Usage

Read how to use the database encryption bundle in your project.
#### [Usage](https://github.com/michaeldegroot/DoctrineEncryptBundle/blob/master/Resources/doc/usage.md)
