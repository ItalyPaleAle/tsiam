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
# Run with default settings (RS256 algorithm)
./tsiam

# Specify a custom hostname
TSIAM_HOSTNAME=my-identity-service ./tsiam

# Use ES256 algorithm (ECDSA with P-256 curve)
./tsiam -algorithm ES256

# Use ES384 algorithm (ECDSA with P-384 curve)
./tsiam -algorithm ES384

# Use ES512 algorithm (ECDSA with P-521 curve)
./tsiam -algorithm ES512

# Use EdDSA algorithm (Ed25519, default curve)
./tsiam -algorithm EdDSA

# Use EdDSA algorithm with explicit curve parameter
./tsiam -algorithm EdDSA -curve ed25519

# Persist signing key to disk (key will be reused across restarts)
./tsiam -key-storage-path /var/lib/tsiam/signing-key.json
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

### Environment Variables

- `TSIAM_HOSTNAME`: The hostname for the tsnet service (default: `tsiam`)

### Command-Line Flags

- `-algorithm`: Signing algorithm for JWTs (default: `RS256`)
  - `RS256`: RSA with SHA-256 (2048-bit key)
  - `ES256`: ECDSA with P-256 curve and SHA-256
  - `ES384`: ECDSA with P-384 curve and SHA-384
  - `ES512`: ECDSA with P-521 curve and SHA-512
  - `EdDSA`: Ed25519 signature algorithm

- `-curve`: Curve for EdDSA algorithm (default: `ed25519`)
  - `ed25519`: Ed25519 curve (currently the only supported curve for EdDSA)

- `-key-storage-path`: Path to persist signing key (optional)
  - If not specified, the key will be ephemeral and regenerated on each restart
  - If specified, the key will be saved to the file and reused across restarts
  - Example: `-key-storage-path /var/lib/tsiam/signing-key.json`

Note: ECDSA curves are automatically selected based on the algorithm (ES256→P-256, ES384→P-384, ES512→P-521).

## Security Considerations

- By default, the service generates ephemeral signing keys on startup. Use `-key-storage-path` to persist keys across restarts.
- When using `-key-storage-path`, ensure the file is stored securely with appropriate file permissions (600).
- JWTs are valid for 1 hour by default.
- The service only listens within your Tailscale network and is not exposed to the public internet.
- Node identity is cryptographically verified using Tailscale's WhoIs API and cannot be spoofed.
- Supported algorithms:
  - **RS256**: RSA with 2048-bit keys (default, widely compatible)
  - **ES256/ES384/ES512**: ECDSA with various curves (smaller keys, better performance)
  - **EdDSA**: Ed25519 (modern, fast, compact signatures)
  
### Key Storage Options

The service supports multiple key storage backends via the `KeyStorage` interface:

- **File Storage** (implemented): Store keys as JSON files on local disk
- **Azure Key Vault Keys** (TODO): Wrap keys with Azure Key Vault managed keys
- **Azure Key Vault Secrets** (TODO): Store keys in Azure Key Vault secrets

To implement additional storage backends, implement the `KeyStorage` interface in `keystorage.go`.

## License

See [LICENSE](LICENSE) file.