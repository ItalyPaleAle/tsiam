---
title: "Quickstart"
weight: 10
---

This guide walks you through running tsiam, connecting it to your Tailnet, and requesting your first token in a few minutes.

## Prerequisites

- A [Tailscale](https://tailscale.com) account and a working Tailnet
- [MagicDNS](https://tailscale.com/kb/1081/magicdns) and [HTTPS certificates](https://tailscale.com/kb/1153/enabling-https) enabled for your Tailnet
- Docker is optional, but recommended

## Step 1: Create a configuration file

Create a `config.yaml` file:

```yaml
# Tailscale network settings
tsnet:
  # Hostname for this node on your Tailnet
  hostname: tsiam
  # Optional: Auth key for automatic authentication with Tailscale
  # (used on first startup only)
  #authKey: tskey-auth-xxx
  # Tag for this node, used in the ACL grant in step 4
  advertiseTags: ["tag:tsiam"]
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
  # Storage backend:
  # "file", "memory", "AzureKeyVaultKeys", or "AzureKeyVaultSecrets"
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

The container runs as user ID 65532. On Linux, make the two state directories writable by that user:

```sh
sudo chown 65532:65532 /path/to/tsnet-state /path/to/tsiam-state
```

### Pre-built Binaries

Download the archive for your platform from the [releases page](https://github.com/ItalyPaleAle/tsiam/releases). For example, on Linux amd64:

```sh
# Set this to the latest version on the releases page
VERSION="v1.x.x"

curl -fsSLO "https://github.com/ItalyPaleAle/tsiam/releases/download/${VERSION}/tsiam-${VERSION}-linux-amd64.tar.gz"

# Verify the release attestation (requires the GitHub CLI)
# Or compare the SHA-256 hash against checksums.txt in the release
gh attestation verify "tsiam-${VERSION}-linux-amd64.tar.gz" --repo ItalyPaleAle/tsiam

tar -xzf "tsiam-${VERSION}-linux-amd64.tar.gz"
./tsiam-${VERSION}-linux-amd64/tsiam
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

1. Generate a [Tailscale auth key](https://login.tailscale.com/admin/settings/keys) in the admin console, with the `tag:tsiam` tag. The tag must be listed in `tagOwners` in your [Tailnet policy](https://login.tailscale.com/admin/acls) first (see step 4).
2. Add it to your config:

   ```yaml
   tsnet:
     authKey: tskey-auth-xxx
   ```

   Or pass it as the `TS_AUTHKEY` environment variable.

Alternatively, you can authenticate via OAuth2 or workload identity federation (see [Configuration](/docs/configuration#authentication)).

> Authentication credentials are only used on first startup or when the node key expires.

## Step 4: Allow nodes to request tokens

By default, a node can only request tokens for the audiences that a Tailscale ACL grant allows. Add a grant to your [Tailnet policy](https://login.tailscale.com/admin/acls):

```json
{
  "tagOwners": {
    "tag:tsiam": ["autogroup:admin"]
  },
  "grants": [
    {
      "src": ["autogroup:member"],
      "dst": ["tag:tsiam"],
      "ip": ["tcp:443"],
      "app": {
        "italypaleale.me/tsiam": [
          { "allowedAudiences": ["https://api.example.com"] }
        ]
      }
    }
  ]
}
```

This grant allows members of your Tailnet to connect to tsiam (`ip`) and request tokens for `https://api.example.com` (`app`). Change `src` to match the users or tags that should be allowed to request tokens. See [Audience authorization](/docs/audience-authorization) for details.

## Step 5: Request a token

From an allowed machine on your Tailnet, request a token using tsiam's full MagicDNS name (replace `tailnet-name` with your Tailnet's DNS name):

> The short name `https://tsiam` does not work because the TLS certificate is only valid for the full name.

```sh
curl -X POST "https://tsiam.tailnet-name.ts.net/token?resource=https://api.example.com" \
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

- [Getting a token](/docs/getting-a-token): full token request reference and code examples
- [Audience authorization](/docs/audience-authorization): control which machines can request which audiences
- [Configuration](/docs/configuration): all configuration options
- [Tailscale Funnel](/docs/tailscale-funnel): expose OIDC endpoints publicly for external token verification
