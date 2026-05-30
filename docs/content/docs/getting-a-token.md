---
title: "Getting a Token"
weight: 20
---

Any machine on your Tailnet can request a JWT token from tsiam by making a `POST` request to the `/token` endpoint.

## Request

```http
POST https://tsiam/token?resource=<audience>
X-Tsiam: 1
```

The `X-Tsiam: 1` header is required and helps preventing cross-site request forgery by ensuring requests are made intentionally.

The `/token` endpoint is only reachable from within your Tailnet. It is never exposed via Tailscale Funnel.

### Query parameters

| Parameter | Required | Description |
|-----------|----------|-------------|
| `resource` | Yes | The audience for the token (alias: `audience`), which specifies the intended recipient of the token. Must be in the [allowed audiences list](/docs/audience-authorization). |

### Common audience values

When exchanging tokens with cloud providers, use these audience values:

| Target service | Audience value |
|----------------|---------------|
| AWS IAM | `sts.amazonaws.com` (for OIDC federation with AWS IAM) |
| Microsoft Entra ID (Azure AD) | `api://AzureADTokenExchange` (for Workload Identity Federation) |
| Google Cloud IAM | Your workload identity pool audience (e.g., `//iam.googleapis.com/projects/PROJECT_ID/locations/global/workloadIdentityPools/POOL_ID/providers/PROVIDER_ID`) |
| Custom API | Use your API's identifier (e.g., `https://api.example.com`) |

## Response

```json
{
  "access_token": "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": "300",
  "expires_on": "1735706000",
  "not_before": "1735700400"
}
```

Present the `access_token` as a Bearer token to the target service.

## JWT claims

The JWT token contains your Tailscale node identity in the `tsiam` claim and the requested audience in the `aud` claim:

```jsonc
{
  // Subject: the stable Tailscale node identifier (see tokens.subjectClaim)
  "sub": "nABC123CNTRL",

  // Issuer: the tsiam service that issued this token
  "iss": "https://your-tsiam",

  // Audience: the intended recipient of this token
  "aud": [ "https://api.example.com" ],

  // Issued At: when the token was created (Unix timestamp)
  "iat": 1735700600,

  // Expiration: when the token expires (Unix timestamp)
  "exp": 1735704000,

  // Not Before: earliest time the token can be used (Unix timestamp)
  "nbf": 1735700600,

  // Custom claim with detailed Tailscale node information
  "tsiam": {
    "nodeId": "abc123",
    "name": "my-server.tailnet-name.ts.net",
    "hostname": "my-server",
    "ip4": "100.64.0.1",
    "ip6": "fd7a:115c:a1e0::1",
    "userLoginName": "user@example.com",
    "tags": []
  },

  // Unique token identifier: cryptographically random 24-byte value encoded as base64url
  // Used for audit and correlation purposes across systems, not for replay prevention
  "jti": "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef"
}
```

By default the `sub` claim is the stable Tailscale node identifier. Set [`tokens.subjectClaim`](./configuration.md#tokenssubjectclaim-values) to `"name"` to use the (recyclable) node name instead (note the security warning in the config docs) or to `"capability"` to pull the subject from the `subject` field of the matching Tailscale ACL grant, letting multiple nodes share one workload identity.

> **Tagged nodes:** for nodes that carry one or more Tailscale tags (`tag:*`), `tsiam.userLoginName` is always emitted as an empty string. The upstream value is the email of whoever authorized the tag, not the workload's owner, so it must not be used as a user-identity signal in relying-party trust policies. Bind tagged-workload trust policies to `tsiam.tags` and `tsiam.nodeId` instead.

### Code Examples

<details>
<summary><strong>cURL</strong></summary>

```sh
# Get a token for a specific audience
TOKEN=$(curl -s -X POST "https://tsiam/token?resource=https://api.example.com" -H "X-Tsiam: 1" | jq -r '.access_token')

# Use the token
curl -H "Authorization: Bearer $TOKEN" https://api.example.com/resource
```

</details>

<details>
<summary><strong>Node.js</strong></summary>

```javascript
async function getToken(audience) {
  const url = new URL('https://tsiam/token');
  url.searchParams.set('resource', audience);

  const response = await fetch(url, {
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
const token = await getToken('https://api.example.com');
const response = await fetch('https://api.example.com/resource', {
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
	"net/url"
)

type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresIn   string `json:"expires_in"`
}

func getToken(audience string) (string, error) {
	u, err := url.Parse("https://tsiam/token")
	if err != nil {
		return "", err
	}
	q := u.Query()
	q.Set("resource", audience)
	u.RawQuery = q.Encode()

	req, err := http.NewRequest("POST", u.String(), nil)
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
    err = json.NewDecoder(resp.Body).Decode(&tokenResp)
	if err != nil {
		return "", err
	}

	return tokenResp.AccessToken, nil
}

func main() {
	token, err := getToken("https://api.example.com")
	if err != nil {
		panic(err)
	}

	// Use the token
	req, _ := http.NewRequest("GET", "https://api.example.com/resource", nil)
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

def get_token(audience):
    response = requests.post(
        "https://tsiam/token",
        params={"resource": audience},
        headers={"X-Tsiam": "1"}
    )
    response.raise_for_status()
    return response.json()["access_token"]

# Usage
token = get_token("https://api.example.com")
response = requests.get(
    "https://api.example.com/resource",
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

    public async Task<string> GetTokenAsync(string audience)
    {
        var uriBuilder = new UriBuilder("https://tsiam/token");
        uriBuilder.Query = $"resource={Uri.EscapeDataString(audience)}";

        var request = new HttpRequestMessage(HttpMethod.Post, uriBuilder.Uri);
        request.Headers.Add("X-Tsiam", "1");

        var response = await _client.SendAsync(request);
        response.EnsureSuccessStatusCode();

        var json = await response.Content.ReadAsStringAsync();
        var tokenResponse = JsonSerializer.Deserialize<TokenResponse>(json,
            new JsonSerializerOptions { PropertyNamingPolicy = JsonNamingPolicy.CamelCase });

        return tokenResponse.AccessToken;
    }

    public async Task<string> CallApiAsync(string url, string audience)
    {
        var token = await GetTokenAsync(audience);

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
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import com.google.gson.Gson;

public class TsiamClient {
    private final HttpClient client = HttpClient.newHttpClient();
    private final Gson gson = new Gson();

    public record TokenResponse(
        String access_token,
        String token_type,
        String expires_in
    ) {}

    public String getToken(String audience) throws Exception {
        String encodedAudience = URLEncoder.encode(audience, StandardCharsets.UTF_8);
        String url = "https://tsiam/token?resource=" + encodedAudience;

        HttpRequest request = HttpRequest.newBuilder()
            .uri(URI.create(url))
            .header("X-Tsiam", "1")
            .POST(HttpRequest.BodyPublishers.noBody())
            .build();

        HttpResponse<String> response = client.send(request,
            HttpResponse.BodyHandlers.ofString());

        TokenResponse tokenResponse = gson.fromJson(response.body(), TokenResponse.class);
        return tokenResponse.access_token();
    }

    public String callApi(String url, String audience) throws Exception {
        String token = getToken(audience);

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