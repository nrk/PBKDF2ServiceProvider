<?php

/*
 * This file is part of the PredisServiceProvider package.
 *
 * (c) Daniele Alessandri <suppakilla@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace Nrk\PBKDF2\Silex;

use Silex\Application;
use Silex\ServiceProviderInterface;
use Nrk\PBKDF2\PBKDF2ServiceProvider as PBKDF2;

class PBKDF2ServiceProviderTest extends \PHPUnit_Framework_TestCase
{
    /**
     * Returns an initialized Silex application with a registered instance
     * of PBKDF2ServiceProvider.
     *
     * @param Array $providerConfiguration Parameters for the provider configuration.
     * @return Application
     */
    protected function getApplication(Array $providerConfiguration = array())
    {
        $app = new Application();
        $app->register(new PBKDF2(), $providerConfiguration);

        return $app;
    }

    /**
     *
     */
    public function testDefaultConfiguration()
    {
        $expected = "6ab15f4d10ae4d40667ed22574f3d645d69382d842bfa55f1c55343ef61df635ccc173b723524ffa64f3a26688450e5a77cb".
                    "de23b4c63ca80e502f1cddc3bdff03d256bccd1d42de715204dfddfd1638d471c0534f13b906ec9529c3a789b6185d728e6b".
                    "c47a56bc872abc25ea5be8fc3f4e564d53c6a3633c1891f0a0bf6e60c5912a87e6e69bcfe90e8cc83094dc1640a69642e53b".
                    "b410ed305e2be62a93b7";

        $app = $this->getApplication(array(
            'pbkdf2.salt' => $salt = 'salt_string',
        ));

        $this->assertSame($salt, $app['pbkdf2.salt']);

        $this->assertSame(PBKDF2::ALGORITHM, $app['pbkdf2.algorithm']);
        $this->assertSame(PBKDF2::KEY_LENGTH, $app['pbkdf2.key_length']);
        $this->assertSame(PBKDF2::ITERATIONS, $app['pbkdf2.iterations']);

        $this->assertSame($expected, $app['pbkdf2']('password'));
    }

    /**
     *
     */
    public function testSaltStringAsArgument()
    {
        $expected = "6ab15f4d10ae4d40667ed22574f3d645d69382d842bfa55f1c55343ef61df635ccc173b723524ffa64f3a26688450e5a77cb".
                    "de23b4c63ca80e502f1cddc3bdff03d256bccd1d42de715204dfddfd1638d471c0534f13b906ec9529c3a789b6185d728e6b".
                    "c47a56bc872abc25ea5be8fc3f4e564d53c6a3633c1891f0a0bf6e60c5912a87e6e69bcfe90e8cc83094dc1640a69642e53b".
                    "b410ed305e2be62a93b7";

        $app = $this->getApplication();

        $this->assertSame($expected, $app['pbkdf2']('password', 'salt_string'));
    }

    /**
     * @expectedException RuntimeException
     * @expectedExceptionMessage Please configure a salt string in "pbkdf2.salt" or pass its value as the second argument.
     */
    public function testUnspecifiedSaltStringThrowsException()
    {
        $app = $this->getApplication();
        $app['pbkdf2']('password');
    }

    /**
     *
     */
    public function testAlgorithmConfiguration()
    {
        $app = $this->getApplication(array(
            'pbkdf2.salt' => 'salt_string',
            'pbkdf2.algorithm' => $algorithm = 'sha256',
        ));

        $this->assertSame($algorithm, $app['pbkdf2.algorithm']);
        $this->assertSame(PBKDF2::KEY_LENGTH * 2, strlen($app['pbkdf2']('password')));
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage Unknown hashing algorithm: foo.
     */
    public function testUnsupportedAlgorithmThrowsException()
    {
        $app = $this->getApplication(array(
            'pbkdf2.salt' => 'salt_string',
            'pbkdf2.algorithm' => 'foo',
        ));
    }

    /**
     *
     */
    public function testKeyLengthConfiguration()
    {
        $app = $this->getApplication(array(
            'pbkdf2.salt' => 'salt_string',
            'pbkdf2.key_length' => $length = 256,
        ));

        $this->assertSame($length, $app['pbkdf2.key_length']);
        $this->assertSame($length * 2, strlen($app['pbkdf2']('password')));
    }

    /**
     *
     */
    public function testIterationsConfiguration()
    {
        $app = $this->getApplication(array(
            'pbkdf2.salt' => 'salt_string',
            'pbkdf2.iterations' => $iterations = 2000,
        ));

        $this->assertSame($iterations, $app['pbkdf2.iterations']);
        $this->assertSame(PBKDF2::KEY_LENGTH * 2, strlen($app['pbkdf2']('password')));
    }

    /**
     *
     */
    public function testCustomFunctionConfiguration()
    {
        $expected = "6ab15f4d10ae4d40667ed22574f3d645d69382d842bfa55f1c55343ef61df635ccc173b723524ffa64f3a26688450e5a77cb".
                    "de23b4c63ca80e502f1cddc3bdff03d256bccd1d42de715204dfddfd1638d471c0534f13b906ec9529c3a789b6185d728e6b".
                    "c47a56bc872abc25ea5be8fc3f4e564d53c6a3633c1891f0a0bf6e60c5912a87e6e69bcfe90e8cc83094dc1640a69642e53b".
                    "b410ed305e2be62a93b7";

        $callable = $this->getMock('stdClass', array('__invoke'));
        $callable->expects($this->once())
                 ->method('__invoke')
                 ->with(PBKDF2::ALGORITHM, 'password', 'salt_string', PBKDF2::ITERATIONS, PBKDF2::KEY_LENGTH)
                 ->will($this->returnValue($expected));

        $app = $this->getApplication(array(
            'pbkdf2.salt' => 'salt_string',
            'pbkdf2.function' => $callable,
        ));

        $this->assertSame($callable, $app['pbkdf2.function']);
        $this->assertSame($expected, $app['pbkdf2']('password'));
    }

    /**
     * @expectedException InvalidArgumentException
     * @expectedExceptionMessage The value of "pbkdf2.function" must be a valid callable object.
     */
    public function testInvalidCustomFunctionThrowsException()
    {
        $app = $this->getApplication(array(
            'pbkdf2.salt' => 'salt_string',
            'pbkdf2.function' => new \stdClass(),
        ));
    }
}
