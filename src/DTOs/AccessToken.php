<?php

namespace dreadkopp\SimpleServiceAuth\DTOs;

/**
 * @property array<string> $allowedServices
 */
class AccessToken
{

    public function __construct(
        public readonly string $token,
        public readonly array $allowedServices
    ) {}

}