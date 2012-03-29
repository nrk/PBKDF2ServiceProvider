# PBKDF2ServiceProvider #

This service provider for __[Silex](http://silex-project.org)__ enables developers to seamlessly leverage the
[Password-Based Key Derivation Function (PBKDF2)](http://www.ietf.org/rfc/rfc2898.txt) in their web applications.
It can automatically choose between a pure-PHP implementation of the algorithm or, if available in the `hash`
extension, the C-based function `hash_pbkdf2()` proposed in [PHP #60813](https://bugs.php.net/bug.php?id=60813).


## Getting started ##

Using this service provider is easy, all you need to do is register its namespace in the autoloader stack and
register an instance of the service provider in the silex application:

``` php
<?php
/* ... */
$app['autoloader']->registerNamespaces(array(
    'Nrk\PBKDF2' => __DIR__.'/../vendor/PBKDF2ServiceProvider/lib',
));

$app->register(new Nrk\PBKDF2\PBKDF2ServiceProvider(), array(
    'pbkdf2.salt' => 'my_salt_string',
));

$app->get('/', function(Silex\Application $app) {
    $key = $app['pbkdf2']('my_password');
});
```

If you are using [Composer](http://getcomposer.org/) to manage the dependencies of your Silex application (which
is highly recommended anyway) you do not need to register the namespace in the autoloader stack since this step
is managed for you by Composer itself.

The only required parameter when registering the service provider instance is `pbkdf2.salt` which stores the
salt string used on each supplied password to calculate the resulting key. Optionally `pbkdf2.salt` can be
omitted, but then you must provide a salt string as the second parameter of the generator method. This can
be useful when you want to use dynamically generated salt strings for each password.

``` php
$key = $app['pbkdf2']('my_password', 'my_salt_string');
```

This is the full list of customizable parameters supported by PBKDF2ServiceProvider:

- `pbkdf2.salt`: common salt string used for each password.
- `pbkdf2.algorithm`: hashing algorithm used to generate the key [default: `sha1`].
- `pbkdf2.key_length`: length in bytes of the resulting key [default: `160`].
- `pbkdf2.iterations`: number of hash iterations performed on the password and salt [default: `1000`].
- `pbkdf2.function`: custom function used to generate the key [default: pure-PHP function or `hash_pbkdf2()` if available].


## Testing ##

In order to be able to run the test suite of the provider you must download [Composer](http://packagist.org/about-composer)
in the root of the repository and then install the needed dependencies.

```bash
$ wget http://getcomposer.org/composer.phar
$ php composer.phar install
$ phpunit
```


## Dependencies ##

- PHP >= 5.3.2


## Project links ##
- [Source code](http://github.com/nrk/PBKDF2ServiceProvider)
- [Issue tracker](http://github.com/nrk/PBKDF2ServiceProvider/issues)


## Author ##

- [Daniele Alessandri](mailto:suppakilla@gmail.com) ([twitter](http://twitter.com/JoL1hAHN))


## License ##

The code for PBKDF2ServiceProvider is distributed under the terms of the __MIT license__ (see LICENSE).
