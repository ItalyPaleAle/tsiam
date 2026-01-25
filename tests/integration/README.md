# Integration Tests

This directory contains integration tests for tsiam that validate the token issuance flow over a real Tailscale network.

## Overview

The integration tests verify that:

- tsiam correctly issues JWT tokens for Tailscale-identified callers
- Token signatures can be verified using the JWKS endpoint
- OIDC discovery endpoints (`/healthz`, `/.well-known/jwks.json`, `/.well-known/openid-configuration`) work correctly
- Error responses are returned for invalid requests (missing headers, invalid audiences, etc.)

## GitHub Actions Setup

The integration tests run automatically in GitHub Actions using [Tailscale Workload Identity Federation](https://tailscale.com/kb/1581/workload-identity-federation) (OIDC). This approach uses short-lived tokens instead of long-lived secrets.

### 1. GitHub Repository Variables

Configure these variables in your repository settings (Settings > Secrets and variables > Actions > Variables):

| Variable | Description |
|----------|-------------|
| `TS_OAUTH_CLIENT_ID` | Client ID from Tailscale trust credential (format: `<tailnet-id>/<credential-id>`) |
| `TS_OAUTH_AUDIENCE` | Audience from Tailscale trust credential (format: `api.tailscale.com/<id>`) |

### 2. Tailscale Admin Console Setup

#### Create OIDC Trust Credential

1. Go to the **[Trust credentials](https://login.tailscale.com/admin/settings/trust-credentials)** page in the Tailscale admin console
2. Click **+ Add a credential**
3. Select **OpenID Connect** as the credential type
4. Select **GitHub** as the issuer
5. Configure the subject claim to match your repository:
   - For all branches: `repo:<owner>/<repo>:*`
   - For specific branch: `repo:<owner>/<repo>:ref:refs/heads/main`
   - For pull requests: `repo:<owner>/<repo>:pull_request`
6. Select the required scope:
   - `Auth Keys: Write` (required to create auth keys for tsiam)
7. Add tags that the credential can use:
   - `tag:ci-runner`
   - `tag:ci-tsiam`
8. Save the credential
9. Copy the **Client ID** and **Audience** values to your GitHub repository variables

#### Configure ACL Policy

Add the following to your Tailscale ACL policy (Access Controls > Edit ACL):

```json
{
  "tagOwners": {
    "tag:ci-runner": ["autogroup:admin"],
    "tag:ci-tsiam": ["autogroup:admin"]
  },
  "acls": [
    {
      "action": "accept",
      "src": ["tag:ci-runner"],
      "dst": ["tag:ci-tsiam:443"]
    }
  ]
}
```

This configuration:

- Allows the admin group to manage both CI tags
- Permits the CI runner (GitHub Actions) to connect to tsiam on port 443

## Running Locally

To run integration tests locally, you need a running tsiam instance accessible over Tailscale.

### Prerequisites

1. Your machine must be connected to the same Tailscale network as tsiam
2. tsiam must be running and reachable

### Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `TSIAM_URL` | Yes | Full URL to tsiam (e.g., `https://tsiam.tailnet-name.ts.net`) |
| `TEST_AUDIENCE` | No | Audience to use in tests (default: `https://test.example.com`) |

### Running the Tests

```bash
# Set environment variables
export TSIAM_URL="https://your-tsiam-hostname.tailnet-name.ts.net"
export TEST_AUDIENCE="https://test.example.com"

# Run integration tests
make test-integration

# Or directly with go test
go test -v -tags integration ./tests/integration/...
```

## Troubleshooting

### "TSIAM_URL environment variable is required"

Ensure you've set the `TSIAM_URL` environment variable before running tests.

### Connection refused / timeout

- Verify tsiam is running and healthy: `curl -k https://<tsiam-host>/healthz`
- Ensure your machine can reach tsiam over Tailscale: `tailscale ping <tsiam-host>`
- Check that ACLs allow traffic from your node to tsiam

### "audience_not_allowed" errors

The test audience must be in tsiam's `allowedAudiences` configuration. For CI, the workflow configures tsiam with `https://test.example.com`. For local testing, ensure your tsiam config includes your test audience.

### OIDC token exchange errors in CI

- Verify the trust credential is configured for the correct repository and branch pattern
- Ensure the credential has both `Devices: Write` and `Auth Keys: Write` scopes
- Check that the tags `tag:ci-runner` and `tag:ci-tsiam` are added to the credential
- Verify `TS_OAUTH_CLIENT_ID` and `TS_OAUTH_AUDIENCE` repository variables are set correctly

### Node not appearing in Tailscale

- The trust credential must have permission to create devices with the specified tags
- Check the Tailscale admin console for any authorization errors
- Verify the ACL policy includes the required `tagOwners` entries
