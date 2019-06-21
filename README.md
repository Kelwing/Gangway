# auth-service
A Golang API for providing JWT-based single sign-on through many different OAuth providers.

## Why?

I was sick of rewriting basic OAuth workflows for every project I work on.  Since every API
I create relies on JWT, it makes sense to just make it its own service.  This service
will produce a public/private key pair, and serve the public key for other services
that rely on it for authentication.  All JWTs are signed with the private key instead of a
symmetric key to provide a super flexible system that can be tied into any environment.