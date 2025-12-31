# tsiam - Workload Identity over Tailscale

A Tailscale-powered workload identity service that provides JWT tokens based on Tailscale node identity. Think of it as a Tailscale version of Kubernetes workload identity (using Service Account Tokens), AWS IAM Roles for EC2, Azure Managed Identity.

## Why tsiam

tsiam lets your applications authenticate themselves based on their Tailscale network identity—no passwords, API keys, or certificates to manage. Any machine on your Tailnet can request a signed JWT token that proves its identity.

- **Zero-credential authentication**: Applications authenticate using their Tailscale identity, without secrets to rotate or leak
- **Standard JWT tokens**: Works with any system that supports JWT/OIDC verification
- **Tailscale-native security**: Token requests are only accepted from authenticated Tailscale nodes
- **Public key verification**: Expose JWKS endpoints via Tailscale Funnel so external services can verify tokens
- **Flexible key storage**: Store signing keys locally, in memory, or securely in Azure Key Vault

## Use Cases

- Grant access to cloud resources (databases, storage, APIs) based on Tailscale node identity
- Enable service-to-service authentication
- Replace static API keys with short-lived, identity-bound tokens
- Integrate Tailscale identity with existing OIDC-compatible systems
- Build zero-trust architectures where every request is authenticated

## Installation

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

### Building from Source

```sh
git clone https://github.com/ItalyPaleAle/tsiam.git
cd tsiam
go build -o tsiam ./cmd
```

## Configuration

tsiam is configured via a YAML file. The application looks for configuration in this order:

1. Path specified in `TSIAM_CONFIG` environment variable
2. `./config.yaml` (current directory)
3. `~/.tsiam/config.yaml`
4. `/etc/tsiam/config.yaml`

### Basic Configuration

Create a `config.yaml` file:

```yaml
# Tailscale network settings
tsnet:
  # Hostname for this node on your Tailnet
  hostname: tsiam
  # Optional: Auth key for automatic authentication with Tailscale (used on first startup only)
  #authKey: tskey-auth-xxx
  # Enable Tailscale Funnel for public OIDC endpoints
  funnel: false

# Token settings
tokens:
  # Token lifetime (min: 1m, max: 24h)
  lifetime: 1h

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

## Quick Start

1. Create a configuration file (see above)
2. Run tsiam (via Docker or binary)
3. On first run, authenticate the tsiam node to your Tailnet (or use an auth key)
4. Request tokens from any machine on your Tailnet

## Getting a JWT Token

To obtain a JWT token, make a `POST` request to `/token` from any machine on your Tailnet. Adding the `X-Tsiam: 1` header is required for security:

```sh
curl -X POST https://tsiam/token -H "X-Tsiam: 1"
```

> **Note**: The `/token` endpoint is only accessible from within your Tailnet. It cannot be accessed via Tailscale Funnel.

### Response

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": "3600",
  "expires_on": "1735706000",
  "not_before": "1735700400"
}
```

The JWT token contains your Tailscale node identity in the `tsiam` claim:

```json
{
  "sub": "nodeId:abc123",
  "iss": "https://your-tsiam",
  "iat": 1735700600,
  "exp": 1735704000,
  "tsiam": {
    "nodeId": "abc123",
    "name": "my-server",
    "ip4": "100.64.0.1",
    "ip6": "fd7a:115c:a1e0::1",
    "userLoginName": "user@example.com",
    "tags": ["tag:webserver"]
  }
}
```

### Code Examples

<details>
<summary><strong>cURL</strong></summary>

```sh
# Get a token
TOKEN=$(curl -s -X POST https://tsiam/token -H "X-Tsiam: 1" | jq -r '.access_token')

# Use the token
curl -H "Authorization: Bearer $TOKEN" https://your-api.example.com/resource
```

</details>

<details>
<summary><strong>Node.js</strong></summary>

```javascript
async function getToken() {
  const response = await fetch('https://tsiam/token', {
    method: 'POST',
    headers: {
      'X-Tsiam': '1',
    },
  });

  if (!response.ok) {
    throw new Error(`Failed to get token: ${response.status}`);
  }

  const data = await response.json();
  return data.access_token;
}

// Usage
const token = await getToken();
const response = await fetch('https://your-api.example.com/resource', {
  headers: {
    'Authorization': `Bearer ${token}`,
  },
});
```

</details>

<details>
<summary><strong>Go</strong></summary>

```go
package main

import (
	"encoding/json"
	"fmt"
	"net/http"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   string `json:"expires_in"`
}

func getToken() (string, error) {
	req, err := http.NewRequest("POST", "https://tsiam/token", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("X-Tsiam", "1")

	client := http.DefaultClient()
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var tokenResp TokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

func main() {
	token, err := getToken()
	if err != nil {
		panic(err)
	}

	// Use the token
	req, _ := http.NewRequest("GET", "https://your-api.example.com/resource", nil)
	req.Header.Set("Authorization", "Bearer "+token)

	client := http.DefaultClient()
	resp, err := client.Do(req)
	if err != nil {
		panic(err)
	}
	defer resp.Body.Close()

	fmt.Println("Response status:", resp.Status)
}
```

</details>

<details>
<summary><strong>Python</strong></summary>

```python
import requests

def get_token():
    response = requests.post(
        "https://tsiam/token",
        headers={"X-Tsiam": "1"}
    )
    response.raise_for_status()
    return response.json()["access_token"]

# Usage
token = get_token()
response = requests.get(
    "https://your-api.example.com/resource",
    headers={"Authorization": f"Bearer {token}"}
)
```

</details>

<details>
<summary><strong>C# (.NET)</strong></summary>

```csharp
using System.Net.Http;
using System.Net.Http.Headers;
using System.Text.Json;

public class TokenResponse
{
    public string AccessToken { get; set; }
    public string TokenType { get; set; }
    public string ExpiresIn { get; set; }
}

public class TsiamClient
{
    private readonly HttpClient _client = new();

    public async Task<string> GetTokenAsync()
    {
        var request = new HttpRequestMessage(HttpMethod.Post, "https://tsiam/token");
        request.Headers.Add("X-Tsiam", "1");

        var response = await _client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        return tokenResponse.AccessToken;
    }

    public async Task<string> CallApiAsync(string url)
    {
        var token = await GetTokenAsync();

        var request = new HttpRequestMessage(HttpMethod.Get, url);
        request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", token);

        var response = await _client.SendAsync(request);
        return await response.Content.ReadAsStringAsync();
    }
}
```

</details>

<details>
<summary><strong>Java</strong></summary>

```java
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import com.google.gson.Gson;

public class TsiamClient {
    private final HttpClient client = HttpClient.newHttpClient();
    private final Gson gson = new Gson();

    public record TokenResponse(
        String access_token,
        String token_type,
        String expires_in
    ) {}

    public String getToken() throws Exception {
        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create("https://tsiam/token"))
            .header("X-Tsiam", "1")
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();

        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());

        TokenResponse tokenResponse = gson.fromJson(response.body(), TokenResponse.class);
        return tokenResponse.access_token();
    }

    public String callApi(String url) throws Exception {
        String token = getToken();

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("Authorization", "Bearer " + token)
            .GET()
            .build();

        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());

        return response.body();
    }
}
```

</details>

## OIDC Endpoints

tsiam provides standard OIDC discovery endpoints for token verification.

These endpoints can be exposed publicly via Tailscale Funnel (see [Configuring Tailscale Funnel](#configuring-tailscale-funnel)), allowing external services to verify tokens issued by tsiam.

### JWKS Endpoint

```http
GET /.well-known/jwks.json
```

Returns the public keys used to sign tokens. Use this to verify JWT signatures.

### OpenID Configuration

```http
GET /.well-known/openid-configuration
```

Returns OIDC discovery metadata including the issuer and JWKS URI.

## Configuring Tailscale Funnel

To allow external services to verify your JWT tokens, you can expose the OIDC endpoints publicly using [Tailscale Funnel](https://tailscale.com/kb/1223/funnel).

1. **Enable Funnel in your configuration**:

   ```yaml
   tsnet:
     hostname: tsiam
     funnel: true
   ```

2. **Ensure Funnel is enabled for your Tailnet**: Funnel must be enabled in your Tailscale admin console. See the [Tailscale Funnel documentation](https://tailscale.com/kb/1223/funnel) for setup instructions.

3. **Verify public access**: Once configured, the OIDC endpoints will be accessible at:
   - `https://tsiam.<your-tailnet>.ts.net/.well-known/jwks.json`
   - `https://tsiam.<your-tailnet>.ts.net/.well-known/openid-configuration`

> **Security Note**: Only the `.well-known` endpoints are exposed via Funnel. The `/token` endpoint remains accessible only from within your Tailnet.

## License

This project is licensed under the MIT License.
