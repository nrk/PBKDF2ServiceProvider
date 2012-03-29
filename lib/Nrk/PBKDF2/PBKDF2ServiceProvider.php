<?php

/*
 * This file is part of the PBKDF2ServiceProvider package.
 *
 * (c) Daniele Alessandri <suppakilla@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nrk\PBKDF2;

use Silex\Application;
use Silex\ServiceProviderInterface;

/**
 * Exposes the Password-Based Key Derivation Function (PBKDF2) to Silex applications
 * using a pure-PHP implementation of the algorithm.
 *
 * This service provider can automatically switch to hash_pbkdf2() if this function
 * has been compiled for the hash extension as proposed in PHP request #60813.
 *
 * @author Daniele Alessandri <suppakilla@gmail.com>
 * @link http://www.ietf.org/rfc/rfc2898.txt
 * @link https://bugs.php.net/bug.php?id=60813
 */
class PBKDF2ServiceProvider implements ServiceProviderInterface
{
    const ALGORITHM = 'sha1';
    const KEY_LENGTH = 160;
    const ITERATIONS = 1000;

    /**
     * Returns the default hashing function detecting if hash_pbkdf2() has been compiled
     * and is available in the hash extension. The hashing function returned by this method
     * must be a callable object compatible with the following signature:
     *
     * function($algorithm, $password, $salt, $iterations, $length)
     *
     * @return mixed
    */
    protected function getHashFunction()
    {
        if (function_exists('hash_pbkdf2')) {
            return function($algorithm, $password, $salt, $iterations, $length) {
                return hash_pbkdf2($algorithm, $password, $salt, $iterations, $length);
            };
        }

        return function($algorithm, $password, $salt, $iterations, $length) {
            $derivedKey = '';

            for ($blockPos = 1; $blockPos < $length; $blockPos++) {
                $block = $hmac = hash_hmac($algorithm, $salt . pack('N', $blockPos), $password, true);
                for ($i = 1; $i < $iterations; $i++) {
                    $block ^= ($hmac = hash_hmac($algorithm, $hmac, $password, true));
                }
                $derivedKey .= $block;
            }

            return bin2hex(substr($derivedKey, 0, $length));
        };
    }

    /**
     * {@inheritdoc}
     */
    public function register(Application $app)
    {
        if (isset($app['pbkdf2.function'])) {
            if (!is_callable($app['pbkdf2.function'])) {
                throw new \InvalidArgumentException('The value of "pbkdf2.function" must be a valid callable object.');
            }
        }
        else {
            $app['pbkdf2.function'] = $app->protect($this->getHashFunction($app));
        }

        if (isset($app['pbkdf2.algorithm'])) {
            if (!in_array($algorithm = $app['pbkdf2.algorithm'], hash_algos())) {
                throw new \InvalidArgumentException("Unknown hashing algorithm: $algorithm.");
            }
        }
        else {
            $app['pbkdf2.algorithm'] = self::ALGORITHM;
        }

        if (!isset($app['pbkdf2.key_length'])) {
            $app['pbkdf2.key_length'] = self::KEY_LENGTH;
        }

        if (!isset($app['pbkdf2.iterations'])) {
            $app['pbkdf2.iterations'] = self::ITERATIONS;
        }

        $app['pbkdf2'] = $app->protect(function($password, $salt = null) use($app) {
            if ($salt === null) {
                if (!isset($app['pbkdf2.salt'])) {
                    throw new \RuntimeException('Please configure a salt string in "pbkdf2.salt" or pass its value as the second argument.');
                }
                $salt = $app['pbkdf2.salt'];
            }

            $arguments = array(
                $app['pbkdf2.algorithm'],
                $password,
                $salt,
                (int) $app['pbkdf2.iterations'],
                (int) $app['pbkdf2.key_length'],
            );

            return call_user_func_array($app['pbkdf2.function'], $arguments);
        });
    }
}
