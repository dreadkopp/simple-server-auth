<?php

return [
    // default store time for access token
    'ttl' => 3600,
    // a list of ips or networks (cidr) that are allowed by default
    'whitelisted' => [
        '127.0.0.1',
        '10.0.0.0/8',
        '172.16.0.0/12',
        '192.168.0.0/16',
    ],
    // the shared cache to use to store the tokens must be the same for all services using this library
    'store' => 'redis'
];