<?php

namespace dreadkopp\SimpleServiceAuth\Providers;

use dreadkopp\SimpleServiceAuth\Services\AccessControlService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\ServiceProvider;

class ServiceAccessServiceProvider extends ServiceProvider
{

    public function register(): void
    {
        $this->app->scoped(
            AccessControlService::class,
            fn() => new AccessControlService(
                Cache::store(Config::get('service-access.store')),
                Config::get('service-access.ttl'))
        );
    }

}