<?php

declare(strict_types=1);

namespace TasmoAdmin\Helper;

use Symfony\Component\HttpFoundation\IpUtils;

class ProxyAuthHelper
{
    /**
     * Whether the request was authenticated by a trusted reverse proxy.
     *
     * Requires TASMO_AUTH_HEADER and TASMO_TRUSTED_PROXIES. The decision is based on the
     * connecting address (REMOTE_ADDR) only, never on X-Forwarded-For.
     *
     * @param array<string, mixed> $server
     */
    public static function isAuthenticatedByProxy(array $server): bool
    {
        $header = trim((string) getenv('TASMO_AUTH_HEADER'));
        $proxies = array_filter(array_map('trim', explode(',', (string) getenv('TASMO_TRUSTED_PROXIES'))));

        if ('' === $header || [] === $proxies) {
            return false;
        }

        $remoteAddr = $server['REMOTE_ADDR'] ?? null;
        if (!is_string($remoteAddr) || !IpUtils::checkIp($remoteAddr, $proxies)) {
            return false;
        }

        $key = 'HTTP_'.strtoupper(str_replace('-', '_', $header));

        return isset($server[$key]) && is_string($server[$key]) && '' !== trim($server[$key]);
    }
}
