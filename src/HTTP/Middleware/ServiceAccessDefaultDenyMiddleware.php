<?php

namespace dreadkopp\SimpleServiceAuth\HTTP\Middleware;

use Closure;
use Illuminate\Http\Request;
use Illuminate\Support\Arr;
use Illuminate\Support\Facades\Config;
use Psr\SimpleCache\InvalidArgumentException;
use Symfony\Component\Finder\Exception\AccessDeniedException;
use Symfony\Component\HttpFoundation\IpUtils;

class ServiceAccessDefaultDenyMiddleware
{

    /**
     * @throws InvalidArgumentException
     */
    public function handle(Request $request, Closure $next)
    {
        if (IpUtils::checkIp($request->getClientIp(), Config::get('service-access.whitelist'))) {
            return $next($request);
        }

        // if serviceAccess is used, check it there
        if (in_array(ServiceAccessMiddleware::class, Arr::flatten($request->route()?->middleware()??[]), true)) {
            return $next($request);
        }

        // else deny
        throw new AccessDeniedException('not allowed to access this service');
    }

}