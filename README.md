this library provides a simple way to authorize access to various laravel-based services by storing a list of service names in a shared cache (i.e. redis)

this library does not provide any kind of authentication. Its just a mechanic to limit access to your api endpoints

by instanciating the ServiceAccessMiddleware each request will be checked for a header
'x-service-access-token'
when present and the current service app.name is in the list of allowed services the request will be handled.

Simple installation is to place ServiceAccessMiddleware to the global HTTP Middleware stack

For a more granular access control add the ServiceAccessDefaultDenyMiddleware to global HTTP Middleware stack, then place
the ServiceAccessMiddleware to specific routes only 
