---
title: "Configuration"
weight: 30
---

tsiam is configured via a YAML file. The application searches for configuration in this order:

1. Path set in the `TSIAM_CONFIG` environment variable
2. `./config.yaml` (current directory)
3. `~/.tsiam/config.yaml`
4. `/etc/tsiam/config.yaml`

> When using Docker, mount `config.yaml` at `/etc/tsiam/config.yaml`. The container runs as user ID 65532, so mounted state directories must be writable by that user.

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

If tsiam can't join the Tailnet within 5 minutes of starting, it exits with an error.

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

- Set `TS_CLIENT_ID`, or `tsnet.clientId`
- Provide the identity token in one of these ways:
  - `tsnet.idTokenFile`: path to a file containing a token
  - `tsnet.idToken` or `TS_ID_TOKEN`: the token itself
  - `tsnet.audience` or `TS_AUDIENCE`: let tsnet request a token from a supported cloud provider
- Add `tsnet.advertiseTags` to your config (for example `["tag:tsiam"]`)

## Configuration reference

### `tsnet`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `tsnet.hostname` | string | `"tsiam"` | Hostname for this node on the Tailnet |
| `tsnet.authKey` | string | — | Tailscale auth key for automatic node registration |
| `tsnet.clientId` | string | - | Tailscale client ID for Workload Identity Federation. Optional attributes can be appended e.g. `?ephemeral=false&preauthorized=true` |
| `tsnet.idToken` | string | - | OIDC token for Workload Identity Federation |
| `tsnet.idTokenFile` | string | - | Path to a file containing an OIDC token, e.g. a projected service account token in Kubernetes |
| `tsnet.audience` | string | - | Audience used to request an ID token from a supported cloud provider |
| `tsnet.stateDir` | string | — | Directory for tsnet state (defaults to a folder next to the config file) |
| `tsnet.ephemeral` | boolean | `false` | If true, the node is ephemeral and not persisted in the Tailnet |
| `tsnet.advertiseTags` | list | — | Tags to apply to this node, used for ACL enforcement |
| `tsnet.funnel` | boolean | `false` | Expose `.well-known` endpoints via Tailscale Funnel |

### `tokens`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `tokens.lifetime` | duration | `"5m"` | Token lifetime (minimum: 1m, maximum: 1h) |
| `tokens.allowedAudiences` | list | **required** | Audiences that can be requested - only these values will be issued |
| `tokens.allowEmptyNodeCapability` | boolean | `false` | If true, nodes without an explicit ACL capability grant can request any globally-allowed audience |
| `tokens.subjectClaim` | string | `"nodeId"` | Value to use for the JWT `sub` claim (see below) |
| `tokens.claimName` | string | `"italypaleale.me/tsiam"` | Name of the custom claim with the caller's Tailscale identity (see [JWT claims](/docs/getting-a-token#jwt-claims)) |
| `tokens.includeCapabilities` | boolean | `false` | If true, include the caller's tsiam capability grants under `capMap` in the identity claim (see [JWT claims](/docs/getting-a-token#jwt-claims)) |

#### `tokens.subjectClaim` values

| Value | Description |
| --- | --- |
| `"nodeId"` (default) | Stable Tailscale node ID (recommended) |
| `"name"` | MagicDNS node name (**⚠ can be reused** if a device is removed and re-created) |
| `"capability"` | The `subject` field from matching Tailscale ACL grants, so multiple nodes can share an identity (see [Shared workload identity](/docs/audience-authorization#shared-workload-identity-via-subject)) |

### `signingKey`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `signingKey.storage` | string | `"file"` | Storage backend: `file`, `memory`, `AzureKeyVaultKeys`, `AzureKeyVaultSecrets` |
| `signingKey.algorithm` | string | `"ES256"` | Signing algorithm: `RS256`, `ES256`, `ES384`, `ES512`, `EdDSA` |

> Microsoft Entra ID only accepts tokens signed with `RS256`. AWS and Google Cloud also accept `ES256`.

> ⚠️ Note: Changing `signingKey.algorithm` does not replace an existing key. To switch algorithms, delete the stored key and restart tsiam.

**File storage** (`signingKey.storage: file`):

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `signingKey.file.storagePath` | string | **required** | Path to store the signing key (not encrypted on disk) |

**Azure Key Vault Keys** (`signingKey.storage: AzureKeyVaultKeys`):

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `signingKey.azureKeyVaultKeys.vaultUrl` | string | **required** | Azure Key Vault URL (e.g. `https://myvault.vault.azure.net/`) |
| `signingKey.azureKeyVaultKeys.keyName` | string | **required** | Name of the RSA key used for wrapping/unwrapping |
| `signingKey.azureKeyVaultKeys.keyVersion` | string | latest | Key version used to wrap new signing keys (empty or `latest` uses the latest version) |
| `signingKey.azureKeyVaultKeys.storagePath` | string | **required** | Path to store the wrapped signing key on disk |
| `signingKey.azureKeyVaultKeys.tenantId` | string | — | Microsoft Entra ID tenant ID |
| `signingKey.azureKeyVaultKeys.clientId` | string | — | Client ID of the application or managed identity |
| `signingKey.azureKeyVaultKeys.clientSecret` | string | — | Client secret of the application |

The wrapped key file records the Key Vault key version used to wrap it. After rotating the key in Key Vault, keep the old version enabled so tsiam can still unwrap the stored key.

**Azure Key Vault Secrets** (`signingKey.storage: AzureKeyVaultSecrets`):

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `signingKey.azureKeyVaultSecrets.vaultUrl` | string | **required** | Azure Key Vault URL (e.g. `https://myvault.vault.azure.net/`) |
| `signingKey.azureKeyVaultSecrets.secretName` | string | **required** | Name of the secret storing the signing key |
| `signingKey.azureKeyVaultSecrets.tenantId` | string | — | Microsoft Entra ID tenant ID |
| `signingKey.azureKeyVaultSecrets.clientId` | string | — | Client ID of the application or managed identity |
| `signingKey.azureKeyVaultSecrets.clientSecret` | string | — | Client secret of the application |

If multiple tsiam instances share the same secret, start one instance first so it creates the signing key before the others start.

**Authenticating with Azure Key Vault**:

- With `clientSecret`, tsiam authenticates with that client secret (`tenantId` and `clientId` are also required).
- With `clientId` only, tsiam uses a user-assigned managed identity, or workload identity when `AZURE_FEDERATED_TOKEN_FILE` is set (such as on AKS).
- Otherwise, tsiam uses [`DefaultAzureCredential`](https://learn.microsoft.com/azure/developer/go/sdk/authentication/credential-chains#defaultazurecredential-overview).

### `logs`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `logs.level` | string | `"info"` | Log level: `debug`, `info`, `warn`, `error` |
| `logs.omitHealthChecks` | boolean | `true` | Suppress log lines for `/healthz` requests |
| `logs.json` | boolean | auto | Emit JSON-formatted logs (defaults to `true` when no TTY is attached) |

### `metrics`

| Option | Type | Default | Description |
| --- | --- | --- | --- |
| `metrics.includeNodeName` | boolean | `false` | Add the caller's node name (`node` attribute) to the `tsiam_auths` metric. Avoid enabling this when using ephemeral nodes, as each node name creates a new time series |

See [Observability](/docs/observability) for exporting logs, metrics, and traces.
