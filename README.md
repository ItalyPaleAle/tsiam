# tsiam - Tailscale Workload Identity Service

A Tailscale-powered workload identity service that provides JWT tokens based on Tailscale node identity. Think of it as a Tailscale version of AWS IAM Roles for EC2 or Azure Managed Identity.

## Overview

`tsiam` uses [tsnet](https://tailscale.com/tsnet) to create a service running inside your Tailscale tailnet. It provides workload identity by issuing JWT tokens that are tied to the Tailscale node making the request.

## Features

- **Automatic Node Identity**: JWTs are issued based on the Tailscale node that requests them
- **OIDC Federation**: Exposes a JWKS endpoint for OpenID Connect federation
- **Secure by Design**: Runs entirely within your Tailscale network
- **Zero Configuration**: Works out of the box with sensible defaults

## Endpoints

### `GET /token` or `POST /token`
Returns a JWT token for the requesting workload. The token contains:
- `node_id`: The Tailscale node ID
- `node_name`: The Tailscale node hostname
- `user_id`: The Tailscale user ID (if available)
- Standard JWT claims (iss, sub, aud, exp, iat, nbf)

**Response:**
```json
{
  "access_token": "eyJhbGciOiJSUzI1NiIsImtpZCI6ImtleS0xNzM...",
  "token_type": "Bearer",
  "expires_in": "3600"
}
```

### `GET /.well-known/jwks.json`
Returns the JSON Web Key Set (JWKS) containing the public keys used to verify JWT signatures. This endpoint is used for OIDC federation.

**Response:**
```json
{
  "keys": [
    {
      "kid": "key-1734000000",
      "kty": "RSA",
      "alg": "RS256",
      "use": "sig",
      "n": "...",
      "e": "AQAB"
    }
  ]
}
```

## Installation

### Build from source

```bash
git clone https://github.com/ItalyPaleAle/tsiam.git
cd tsiam
go build -o tsiam .
```

### Run

```bash
# Run with default hostname "tsiam"
./tsiam

# Or specify a custom hostname
TSIAM_HOSTNAME=my-identity-service ./tsiam
```

On first run, you'll be prompted to authenticate with Tailscale. The service will then be available at `https://<hostname>` within your tailnet.

## Usage Example

From any machine in your tailnet:

```bash
# Get a token
curl https://tsiam/token

# View the JWKS
curl https://tsiam/.well-known/jwks.json
```

## Use Cases

- **Service-to-Service Authentication**: Services can authenticate to each other using JWTs instead of shared secrets
- **Cloud Provider Integration**: Use OIDC federation to assume AWS IAM roles or Azure identities from your Tailscale network
- **API Authorization**: Validate requests based on the Tailscale node identity
- **Zero Trust Architecture**: Implement workload identity without managing credentials

## Configuration

Configure via environment variables:

- `TSIAM_HOSTNAME`: The hostname for the tsnet service (default: `tsiam`)

## Security Considerations

- The service generates a new RSA keypair on startup. Keys are not persisted between restarts.
- JWTs are valid for 1 hour by default.
- The service only listens within your Tailscale network and is not exposed to the public internet.
- Node identity is derived from the Tailscale connection metadata.

## License

See [LICENSE](LICENSE) file.