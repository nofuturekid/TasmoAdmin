<?php

namespace Tests\TasmoAdmin\Helper;

use PHPUnit\Framework\TestCase;
use TasmoAdmin\Helper\ProxyAuthHelper;

class ProxyAuthHelperTest extends TestCase
{
    protected function setUp(): void
    {
        putenv('TASMO_AUTH_HEADER=X-authentik-username');
        putenv('TASMO_TRUSTED_PROXIES=172.18.0.5,10.0.0.0/8,fd00::/8');
    }

    protected function tearDown(): void
    {
        putenv('TASMO_AUTH_HEADER');
        putenv('TASMO_TRUSTED_PROXIES');
    }

    public function testTrustedProxyWithHeaderIsAuthenticated(): void
    {
        self::assertTrue(ProxyAuthHelper::isAuthenticatedByProxy([
            'REMOTE_ADDR' => '172.18.0.5',
            'HTTP_X_AUTHENTIK_USERNAME' => 'thomas',
        ]));
    }

    public function testUntrustedAddressWithHeaderIsNotAuthenticated(): void
    {
        self::assertFalse(ProxyAuthHelper::isAuthenticatedByProxy([
            'REMOTE_ADDR' => '192.168.1.50',
            'HTTP_X_AUTHENTIK_USERNAME' => 'thomas',
        ]));
    }

    public function testForwardedForCannotSpoofTrustedAddress(): void
    {
        self::assertFalse(ProxyAuthHelper::isAuthenticatedByProxy([
            'REMOTE_ADDR' => '192.168.1.50',
            'HTTP_X_FORWARDED_FOR' => '172.18.0.5',
            'HTTP_X_AUTHENTIK_USERNAME' => 'thomas',
        ]));
    }

    public function testTrustedProxyWithoutHeaderIsNotAuthenticated(): void
    {
        self::assertFalse(ProxyAuthHelper::isAuthenticatedByProxy(['REMOTE_ADDR' => '172.18.0.5']));
    }

    public function testTrustedProxyWithEmptyHeaderIsNotAuthenticated(): void
    {
        self::assertFalse(ProxyAuthHelper::isAuthenticatedByProxy([
            'REMOTE_ADDR' => '172.18.0.5',
            'HTTP_X_AUTHENTIK_USERNAME' => '',
        ]));
    }

    public function testHeaderNameIsCaseInsensitive(): void
    {
        putenv('TASMO_AUTH_HEADER=x-AUTHENTIK-username');

        self::assertTrue(ProxyAuthHelper::isAuthenticatedByProxy([
            'REMOTE_ADDR' => '172.18.0.5',
            'HTTP_X_AUTHENTIK_USERNAME' => 'thomas',
        ]));
    }

    public function testInactiveWhenOnlyHeaderIsConfigured(): void
    {
        putenv('TASMO_TRUSTED_PROXIES');

        self::assertFalse(ProxyAuthHelper::isAuthenticatedByProxy([
            'REMOTE_ADDR' => '172.18.0.5',
            'HTTP_X_AUTHENTIK_USERNAME' => 'thomas',
        ]));
    }

    public function testInactiveWhenOnlyProxiesAreConfigured(): void
    {
        putenv('TASMO_AUTH_HEADER');

        self::assertFalse(ProxyAuthHelper::isAuthenticatedByProxy([
            'REMOTE_ADDR' => '172.18.0.5',
            'HTTP_X_AUTHENTIK_USERNAME' => 'thomas',
        ]));
    }

    public function testCidrMatching(): void
    {
        $server = ['HTTP_X_AUTHENTIK_USERNAME' => 'thomas'];

        self::assertTrue(ProxyAuthHelper::isAuthenticatedByProxy($server + ['REMOTE_ADDR' => '10.20.30.40']));
        self::assertFalse(ProxyAuthHelper::isAuthenticatedByProxy($server + ['REMOTE_ADDR' => '11.0.0.1']));
    }

    public function testIpv6Matching(): void
    {
        $server = ['HTTP_X_AUTHENTIK_USERNAME' => 'thomas'];

        self::assertTrue(ProxyAuthHelper::isAuthenticatedByProxy($server + ['REMOTE_ADDR' => 'fd12:3456::1']));
        self::assertFalse(ProxyAuthHelper::isAuthenticatedByProxy($server + ['REMOTE_ADDR' => '2001:db8::1']));
    }

    public function testMissingRemoteAddrIsNotAuthenticated(): void
    {
        self::assertFalse(ProxyAuthHelper::isAuthenticatedByProxy(['HTTP_X_AUTHENTIK_USERNAME' => 'thomas']));
    }
}
