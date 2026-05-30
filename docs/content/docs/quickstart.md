---
title: "Quickstart"
weight: 10
---

This guide walks you through running tsiam, connecting it to your Tailnet, and requesting your first token in a few minutes.

## Prerequisites

- A [Tailscale](https://tailscale.com) account and a working Tailnet
- Docker is optional, but recommended

## Step 1: Create a configuration file

Create a `config.yaml` file:

```yaml
# Tailscale network settings
tsnet:
  # Hostname for this node on your Tailnet
  hostname: tsiam
  # Optional: Auth key for automatic authentication with Tailscale (used on first startup only)
  #authKey: tskey-auth-xxx
  # Optional: Advertise tags for ACLs (often needed for OAuth2 / federation-based node auth)
  #advertiseTags: ["tag:tsiam"]
  # Enable Tailscale Funnel for public OIDC endpoints
  funnel: false

# Token settings
tokens:
  # Token lifetime (min: 1m, max: 1h)
  lifetime: 5m
  # Global allowlist of audiences tokens can be requested for
  allowedAudiences:
    - "https://api.example.com"

# Signing key configuration
signingKey:
  # Storage backend: "file", "memory", "AzureKeyVaultKeys", or "AzureKeyVaultSecrets"
  storage: file
  # Signing algorithm: RS256, ES256, ES384, ES512, or EdDSA
  algorithm: ES256
  # File storage settings (when storage: file)
  file:
    storagePath: /var/lib/tsiam/signing-key.json

# Logging
logs:
  level: info
```

## Step 2: Run tsiam

### Using Docker (recommended)

Pull and run the container image:

```sh
docker run -d \
  --name tsiam \
  -v /path/to/config.yaml:/etc/tsiam/config.yaml:ro \
  -v /path/to/tsnet-state:/etc/tsiam/tsnet \
  -v /path/to/tsiam-state:/var/lib/tsiam \
  ghcr.io/italypaleale/tsiam:v0
```

### Pre-built Binaries

Download the latest binary for your platform from the [releases page](https://github.com/ItalyPaleAle/tsiam/releases).

```sh
# Example for Linux amd64
curl -L -o tsiam https://github.com/ItalyPaleAle/tsiam/releases/latest/download/tsiam-linux-amd64
chmod +x tsiam
./tsiam
```

The application looks for the configuration file in this order:

1. Path specified in `TSIAM_CONFIG` environment variable
2. `./config.yaml` (current directory)
3. `~/.tsiam/config.yaml`
4. `/etc/tsiam/config.yaml`

### Building from Source

```sh
git clone https://github.com/ItalyPaleAle/tsiam.git
cd tsiam
go build -o tsiam ./cmd
```

## Step 3: Authenticate the node

On first startup, tsiam needs to join your Tailnet. The simplest way is an auth key:

1. Generate a [Tailscale auth key](https://login.tailscale.com/admin/settings/keys) in the admin console.
2. Add it to your config:

   ```yaml
   tsnet:
     authKey: tskey-auth-xxx
   ```

   Or pass it as the `TS_AUTHKEY` environment variable.

Alternatively, you can authenticate via OAuth2 or workload identity federation — see [Configuration](/docs/configuration#authentication) for details.

> Authentication credentials are only used on first startup or when the node key expires.

## Step 4: Request a token

From any machine on your Tailnet:

```sh
curl -X POST "https://tsiam/token?resource=https://api.example.com" \
  -H "X-Tsiam: 1"
```

You'll receive a JWT response:

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": "300",
  "expires_on": "1735706000",
  "not_before": "1735700400"
}
```

Use the `access_token` as a Bearer token when calling the target service.

## Next steps

- [Getting a token](/docs/getting-a-token) — full token request reference and code examples
- [Audience authorization](/docs/audience-authorization) — control which machines can request which audiences
- [Configuration](/docs/configuration) — all configuration options
- [Tailscale Funnel](/docs/tailscale-funnel) — expose OIDC endpoints publicly for external token verification
