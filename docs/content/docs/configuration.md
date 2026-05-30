---
title: "Configuration"
weight: 30
---

tsiam is configured via a YAML file. The application searches for configuration in this order:

1. Path set in the `TSIAM_CONFIG` environment variable
2. `./config.yaml` (current directory)
3. `~/.tsiam/config.yaml`
4. `/etc/tsiam/config.yaml`

> When using Docker, mount the `config.yaml` file in `/etc/tsiam/config.yaml`

## Example configuration

```yaml
tsnet:
  hostname: tsiam
  funnel: false

tokens:
  lifetime: 5m
  allowedAudiences:
    - "https://api.example.com"
    - "api://AzureADTokenExchange"
    - "sts.amazonaws.com"

signingKey:
  storage: file
  algorithm: ES256
  file:
    storagePath: /var/lib/tsiam/signing-key.json

logs:
  level: info
```

## Authentication

When tsiam starts for the first time, it needs to join your Tailnet.

> Authentication credentials are only used on first startup or when the node key expires.

You have three options:

### Auth key

Generate a [Tailscale auth key](https://login.tailscale.com/admin/settings/keys) in the admin console:

```yaml
tsnet:
  authKey: tskey-auth-xxx
```

Or pass it as the `TS_AUTHKEY` (alias `TS_AUTH_KEY`) environment variable.

### OAuth2 client

Create a Tailscale OAuth client in the admin portal, then:

- Set the `TS_CLIENT_SECRET` environment variable to the OAuth client secret
- Add `tsnet.advertiseTags` to your config (tags are required for OAuth-based registration):

  ```yaml
  tsnet:
    advertiseTags: ["tag:tsiam"]
  ```

### Workload identity federation (OIDC)

If tsiam itself runs in a cloud environment that provides OIDC tokens (e.g., AWS, Azure, GCP, GitHub Actions), it can join the Tailnet using its own workload identity:

- Set `TS_CLIENT_ID`
- Set either `TS_ID_TOKEN` (provide a token directly) or `TS_AUDIENCE` (let tsnet request an ID token from a supported provider)
- Add `tsnet.advertiseTags` to your config (for example `["tag:tsiam"]`)

## Configuration reference

### `tsnet`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tsnet.hostname` | string | `"tsiam"` | Hostname for this node on the Tailnet |
| `tsnet.authKey` | string | — | Tailscale auth key for automatic node registration |
| `tsnet.stateDir` | string | — | Directory for tsnet state (defaults to a folder next to the config file) |
| `tsnet.ephemeral` | boolean | `false` | If true, the node is ephemeral and not persisted in the Tailnet |
| `tsnet.advertiseTags` | list | — | Tags to apply to this node, used for ACL enforcement |
| `tsnet.funnel` | boolean | `false` | Expose `.well-known` endpoints via Tailscale Funnel |

### `tokens`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `tokens.lifetime` | duration | `"5m"` | Token lifetime (minimum: 1m, maximum: 1h) |
| `tokens.allowedAudiences` | list | **required** | Audiences that can be requested; only these values will be issued |
| `tokens.allowEmptyNodeCapability` | boolean | `false` | If true, nodes without an explicit ACL capability grant can request any globally-allowed audience |
| `tokens.subjectClaim` | string | `"nodeId"` | Value to use for the JWT `sub` claim — see below |

#### `tokens.subjectClaim` values

| Value | Description |
|-------|-------------|
| `"nodeId"` (default) | Stable Tailscale node identifier — recommended |
| `"name"` | MagicDNS node name — **⚠ can be reused** if the device is removed and re-created |
| `"capability"` | The `subject` field from the matching Tailscale ACL grant, allowing multiple nodes to share one workload identity |

### `signingKey`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `signingKey.storage` | string | `"file"` | Storage backend: `file`, `memory`, `AzureKeyVaultKeys`, `AzureKeyVaultSecrets` |
| `signingKey.algorithm` | string | `"ES256"` | Signing algorithm: `RS256`, `ES256`, `ES384`, `ES512`, `EdDSA` |

**File storage** (`signingKey.storage: file`):

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `signingKey.file.storagePath` | string | **required** | Path to store the signing key (not encrypted on disk) |

**Azure Key Vault Keys** (`signingKey.storage: AzureKeyVaultKeys`):

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `signingKey.azureKeyVaultKeys.vaultUrl` | string | **required** | Azure Key Vault URL (e.g. `https://myvault.vault.azure.net/`) |
| `signingKey.azureKeyVaultKeys.keyName` | string | **required** | Name of the key used for wrapping/unwrapping |
| `signingKey.azureKeyVaultKeys.storagePath` | string | **required** | Path to store the wrapped signing key on disk |
| `signingKey.azureKeyVaultKeys.tenantId` | string | — | Azure AD tenant ID (uses `DefaultAzureCredential` if empty) |
| `signingKey.azureKeyVaultKeys.clientId` | string | — | Azure AD application client ID |
| `signingKey.azureKeyVaultKeys.clientSecret` | string | — | Azure AD application client secret |

**Azure Key Vault Secrets** (`signingKey.storage: AzureKeyVaultSecrets`):

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `signingKey.azureKeyVaultSecrets.vaultUrl` | string | **required** | Azure Key Vault URL |
| `signingKey.azureKeyVaultSecrets.secretName` | string | **required** | Name of the secret storing the signing key |
| `signingKey.azureKeyVaultSecrets.tenantId` | string | — | Azure AD tenant ID |
| `signingKey.azureKeyVaultSecrets.clientId` | string | — | Azure AD application client ID |
| `signingKey.azureKeyVaultSecrets.clientSecret` | string | — | Azure AD application client secret |

### `logs`

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `logs.level` | string | `"info"` | Log level: `debug`, `info`, `warn`, `error` |
| `logs.omitHealthChecks` | boolean | `true` | Suppress log lines for `/healthz` requests |
| `logs.json` | boolean | auto | Emit JSON-formatted logs (defaults to `true` when no TTY is attached) |
