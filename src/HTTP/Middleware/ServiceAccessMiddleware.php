<?php

namespace dreadkopp\SimpleServiceAuth\HTTP\Middleware;

use Closure;
use dreadkopp\SimpleServiceAuth\Services\AccessControlService;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\App;
use Illuminate\Support\Facades\Config;
use Psr\SimpleCache\InvalidArgumentException;
use Symfony\Component\Finder\Exception\AccessDeniedException;
use Symfony\Component\HttpFoundation\IpUtils;
use Symfony\Component\HttpFoundation\Response;

class ServiceAccessMiddleware
{

    /**
     * @throws InvalidArgumentException
     */
    public function handle(Request $request, Closure $next)
    {
        if (IpUtils::checkIp($request->getClientIp(), Config::get('service-access.whitelist'))) {
            return $next($request);
        }

        /** @var AccessControlService $accessControlService */
        $accessControlService = App::make(AccessControlService::class);

        $token = $request->header('x-service-access-token');

        if (!$token || !$accessControlService->checkAccess($token)) {
            throw new AccessDeniedException('not allowed to access this service');
        }

        $response = $next($request);

        if ($response instanceof Response) {
            $response->headers->set('x-service-access-token', $token);
        }

        $accessControlService->refreshToken($token);

        return $response;
    }

}