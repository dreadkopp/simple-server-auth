<?php

namespace dreadkopp\SimpleServiceAuth\Tests;

use dreadkopp\SimpleServiceAuth\DTOs\AccessToken;
use dreadkopp\SimpleServiceAuth\HTTP\Middleware\ServiceAccessDefaultDenyMiddleware;
use dreadkopp\SimpleServiceAuth\HTTP\Middleware\ServiceAccessMiddleware;
use dreadkopp\SimpleServiceAuth\Providers\ServiceAccessServiceProvider;
use dreadkopp\SimpleServiceAuth\Services\AccessControlService;
use Illuminate\Support\Facades\Cache;
use Illuminate\Support\Facades\Config;
use Illuminate\Support\Facades\Route;
use Orchestra\Testbench\TestCase;
use Symfony\Component\Finder\Exception\AccessDeniedException;

/**
 * @covers \dreadkopp\SimpleServiceAuth\HTTP\Middleware\ServiceAccessMiddleware
 * @covers \dreadkopp\SimpleServiceAuth\HTTP\Middleware\ServiceAccessDefaultDenyMiddleware
 * @covers \dreadkopp\SimpleServiceAuth\DTOs\AccessToken
 * @covers \dreadkopp\SimpleServiceAuth\Services\AccessControlService
 * @covers \dreadkopp\SimpleServiceAuth\Providers\ServiceAccessServiceProvider
 *
 */
class TestMiddleware extends TestCase
{
    protected ?AccessToken         $allowedToken;
    protected ?AccessToken         $deniedToken;

    protected function setUp(): void
    {
        parent::setUp();
        Route::get('testWithoutMiddlewares', static fn()=>'hello');
        Route::get('testWithBothMiddlewares', static fn()=>'hello')
            ->middleware([
                ServiceAccessMiddleware::class,
                ServiceAccessDefaultDenyMiddleware::class
            ]);
        Route::get('testWithExplicitMiddlewareOnly', static fn()=>'hello')
            ->middleware([ServiceAccessMiddleware::class]);

        Route::get('testWithDefaultDenyMiddlewareOnly', static fn()=>'hello')
            ->middleware([ServiceAccessDefaultDenyMiddleware::class]);

        Config::set('app.name','TESTAPP');
        Config::set('service-access.whitelist', ['10.0.0.0/16','172.0.0.2']);
        Config::set('service-access.store','array');
        Config::set('service-access.ttl',300);

        $this->app->register(ServiceAccessServiceProvider::class);

        /** @var AccessControlService $service */
        $service = $this->app->make(AccessControlService::class);
        $this->app->instance(AccessControlService::class, $service);

        $this->allowedToken = $service->generateToken(['TESTAPP']);
        $this->deniedToken = $service->generateToken(['FOOBAR']);
        $service->storeAccessToken($this->allowedToken);
        $service->storeAccessToken($this->deniedToken);


    }

    public static function tokenProvider():array
    {
        return [
            'no token no restrict' => [
                'used token' => 'none',
                'gains access' => true,
                'uri' => 'testWithoutMiddlewares'
            ],
            'no token but restrict' => [
                'used token' => 'none',
                'gains access' => false,
                'uri' => 'testWithBothMiddlewares'
            ],
            'no token but restrict explicit' => [
                'used token' => 'none',
                'gains access' => false,
                'uri' => 'testWithExplicitMiddlewareOnly'
            ],
            'no token default deny only' => [
                'used token' => 'none',
                'gains access' => false,
                'uri' => 'testWithDefaultDenyMiddlewareOnly'
            ],
            'invalid token no restrict' => [
                'used token' => 'denied',
                'gains access' => true,
                'uri' => 'testWithoutMiddlewares'
            ],
            'invalid token but restrict' => [
                'used token' => 'denied',
                'gains access' => false,
                'uri' => 'testWithBothMiddlewares'
            ],
            'invalid token but restrict explicit' => [
                'used token' => 'denied',
                'gains access' => false,
                'uri' => 'testWithExplicitMiddlewareOnly'
            ],
            'invalid token default deny only' => [
                'used token' => 'denied',
                'gains access' => false,
                'uri' => 'testWithDefaultDenyMiddlewareOnly'
            ],
            'valid token no restrict' => [
                'used token' => 'allowed',
                'gains access' => true,
                'uri' => 'testWithoutMiddlewares'
            ],
            'valid token but restrict' => [
                'used token' => 'allowed',
                'gains access' => true,
                'uri' => 'testWithBothMiddlewares'
            ],
            'valid token but restrict explicit' => [
                'used token' => 'allowed',
                'gains access' => true,
                'uri' => 'testWithExplicitMiddlewareOnly'
            ],
            'valid token default deny only' => [
                'used token' => 'allowed',
                'gains access' => false,
                'uri' => 'testWithDefaultDenyMiddlewareOnly'
            ],
        ];
    }

    /** @dataProvider tokenProvider */
    public function testAccessViaToken(string $tokenType, bool $accessAllowed, string $uri) :void
    {
        
        $token = match ($tokenType) {
            'denied' => $this->deniedToken->token,
            'allowed' => $this->allowedToken->token,
            default => ''
        };
        
        if (!$accessAllowed) {
            $this->expectException(AccessDeniedException::class);
            $this->expectExceptionMessage('not allowed to access this service');
        }
        
        $this->handleExceptions([]);
        $this->withHeader('x-service-access-token', $token)
            ->get($uri)
            ->assertOk()
            ->assertSee('hello');
    }


    public static function ipProvider():array
    {
        return [
            'explicit IP no restrict' => [
                'ip' => '172.0.0.2',
                'gains access' => true,
                'uri' => 'testWithoutMiddlewares'
            ],
            'explicit ip but restrict' => [
                'ip' => '172.0.0.2',
                'gains access' => true,
                'uri' => 'testWithBothMiddlewares'
            ],
            'explicit ip but restrict explicit' => [
                'ip' => '172.0.0.2',
                'gains access' => true,
                'uri' => 'testWithExplicitMiddlewareOnly'
            ],
            'explicit ip but default deny only' => [
                'ip' => '172.0.0.2',
                'gains access' => true,
                'uri' => 'testWithDefaultDenyMiddlewareOnly'
            ],
            'network IP no restrict' => [
                'ip' => '10.0.4.122',
                'gains access' => true,
                'uri' => 'testWithoutMiddlewares'
            ],
            'network ip but restrict' => [
                'ip' => '10.0.4.122',
                'gains access' => true,
                'uri' => 'testWithBothMiddlewares'
            ],
            'network ip but restrict explicit' => [
                'ip' => '10.0.4.122',
                'gains access' => true,
                'uri' => 'testWithExplicitMiddlewareOnly'
            ],
            'network ip but default deny only' => [
                'ip' => '10.0.4.122',
                'gains access' => true,
                'uri' => 'testWithDefaultDenyMiddlewareOnly'
            ],
            'alien IP no restrict' => [
                'ip' => '8.8.8.8',
                'gains access' => true,
                'uri' => 'testWithoutMiddlewares'
            ],
            'alien ip but restrict' => [
                'ip' => '8.8.8.8',
                'gains access' => false,
                'uri' => 'testWithBothMiddlewares'
            ],
            'alien ip but restrict explicit' => [
                'ip' => '8.8.8.8',
                'gains access' => false,
                'uri' => 'testWithExplicitMiddlewareOnly'
            ],
            'alien ip but default deny only' => [
                'ip' => '8.8.8.8',
                'gains access' => false,
                'uri' => 'testWithDefaultDenyMiddlewareOnly'
            ],
        ];
    }

    /** @dataProvider ipProvider */
    public function testViaIp(string $ip, bool $accessAllowed, string $uri) :void
    {
        if (!$accessAllowed) {
            $this->expectException(AccessDeniedException::class);
            $this->expectExceptionMessage('not allowed to access this service');
        }

        $this->handleExceptions([]);
        $this->withServerVariables(['REMOTE_ADDR' => $ip]);
        $this
            ->get($uri)
            ->assertOk()
            ->assertSee('hello');
    }
}