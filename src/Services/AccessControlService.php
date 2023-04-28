<?php

namespace dreadkopp\SimpleServiceAuth\Services;

use dreadkopp\SimpleServiceAuth\DTOs\AccessToken;
use Illuminate\Contracts\Cache\Repository;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Str;
use Psr\SimpleCache\InvalidArgumentException;

class AccessControlService
{

    public function __construct(
        protected readonly Repository $cache,
        protected readonly int $ttl,
    )
    {
    }

    /**
     * @throws InvalidArgumentException
     */
    public function checkAccess(string $token) :bool
    {
        $accessToken = $this->loadAccess($token);

        return in_array(Config::get('app.name'), $accessToken->allowedServices, true);
    }

    /**
     * @throws InvalidArgumentException
     */
    protected function loadAccess(string $token) :AccessToken
    {
        return Cache::store('array')
            ->remember(
                'service-access:'.$token,
                0,
                fn() =>  new AccessToken($token, $this->cache->get($token,[]))
            );
    }

    /** @param array<string> $allowedServices */
    public function generateToken(array $allowedServices) :AccessToken
    {
        return new AccessToken(Str::uuid(), $allowedServices);
    }

    /**
     * @throws InvalidArgumentException
     */
    public function refreshToken($token) :bool
    {
        return $this->storeAccessToken($this->loadAccess($token));
    }



    public function storeAccessToken(AccessToken $token) :bool
    {
        return $this->cache
            ->put(
                $token->token,
                $token->allowedServices,
                $this->ttl
            );
    }

}