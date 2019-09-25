# Gangway
A Golang service for providing Single sign-on using JSON Web Tokens using any public OAuth2 provider
for authentication.

## Introduction
Gangway is designed to provide a separate authentication service that can be plugged into any
project that utilizes OAuth2 from one or more public OAuth2 providers.

It works by running users through a typical OAuth2 flow, obtains the token from the provider,
stores the token, provider name that you specify, and expire time in a JWT and signs the
JWT using an RSA private key that you provide, or you can let Gangway generate one for you.

The public key is then exposed over an HTTP endpoint, so you can validate the web tokens
across any number of services you want to tie in.

## Features

- [x] Auth with any OAuth2 provider
- [x] Redirect back to a custom URL to pass the JWT back to your application
- [x] Built-in login page
- [x] Implements OAuth 2 state parameter
- [ ] Custom token manipulation
- [ ] Automatic config reloading using filesystem watchers

## Configuration
The configuration file is located in config/config.yaml.  Upon first run, a sample config
will be generated for you. 

```yaml
customization:
  app_name: Gangway Test
  logo_url: ""
  site_url: ""
security:
  public_key: ssl/auth.pem.pub
  private_key: ssl/auth.pem
  bit_size: 4096
providers:
- config:
    clientid: 0123456789
    clientsecret: xxxx
    endpoint:
      authurl: https://discordapp.com/api/oauth2/authorize
      tokenurl: https://discordapp.com/api/oauth2/token
      authstyle: 0
    redirecturl: http://localhost:8989/authorize
    scopes:
      - identify
      - email
      - guilds
  enabled: true
  name: Discord
  post_auth_redirect: http://localhost:8989/authtest
```

## Building
We use Go Modules for dependency tracking.  Ensure you have Modules enabled.
```bash
export GO111MODULE=on;
```

To produce a binary, simply using the Go tooling to build.
```bash
go build -o gangway
```

## Running
All configuration is done using the config.yaml file.

Ensure the config is located at `config/config.yaml` and run using `./gangway`

## Docker
We provide public Docker images on Dockerhub.

We recommend storing the RSA keys and config in a Docker volume.

```bash
docker run -v config:/config -v ssl:/ssl -p 8989:8989 kelwing/gangway
```
