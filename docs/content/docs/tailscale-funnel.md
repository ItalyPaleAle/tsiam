---
title: "Tailscale Funnel"
weight: 50
---

External services that need to verify tsiam-issued tokens must be able to fetch the public keys tsiam uses to sign them. [Tailscale Funnel](https://tailscale.com/kb/1223/funnel) lets you expose those OIDC discovery endpoints on the public internet without opening any other part of tsiam.

## What gets exposed

When Funnel is enabled, tsiam exposes two read-only endpoints publicly:

| Endpoint | Description |
|----------|-------------|
| `GET /.well-known/openid-configuration` | OIDC discovery metadata (issuer, JWKS URI) |
| `GET /.well-known/jwks.json` | Public signing keys used to verify JWT signatures |

The `/token` endpoint is **never** exposed via Funnel. Token issuance remains exclusively accessible from within your Tailnet.

## Setup

### 1. Enable Funnel in configuration

```yaml
tsnet:
  hostname: tsiam
  funnel: true
```

### 2. Enable Funnel for your Tailnet

Funnel must be enabled for your Tailscale account before it works. Follow the [Tailscale Funnel setup guide](https://tailscale.com/kb/1223/funnel) to enable it in your admin console.

### 3. Verify public access

Once tsiam restarts with Funnel enabled, the OIDC endpoints are publicly reachable at:

```
https://tsiam.<your-tailnet>.ts.net/.well-known/openid-configuration
https://tsiam.<your-tailnet>.ts.net/.well-known/jwks.json
```

These URLs are what you provide to external services (AWS, Azure, GCP, etc, or your APIs) when configuring an OIDC identity provider.

## Using the issuer URL with cloud providers

When configuring workload identity federation on a cloud provider, you will be asked for an **issuer URL**. Use the public Funnel URL of your tsiam instance:

```
https://tsiam.<your-tailnet>.ts.net
```

The cloud provider will fetch `<issuer>/.well-known/openid-configuration` to discover the JWKS endpoint, then use `<issuer>/.well-known/jwks.json` to validate token signatures.

See the [Getting a token](/docs/getting-a-token#common-audience-values) page for the audience values to use with each provider.
