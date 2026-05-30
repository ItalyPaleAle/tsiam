---
title: "tsiam"
nav_title: "Introduction"
weight: 10
---

tsiam is a Tailscale-powered workload identity service that provides identity tokens based on the node identity in the tailnet. Think of it as a Tailscale version of Kubernetes workload identity (using Service Account Tokens), AWS IAM Roles for EC2, Azure Managed Identity.

Any application running on your Tailnet can ask tsiam for a short-lived JWT token that proves who it is. External services — cloud APIs, databases, your own back-ends — can verify that token using standard OIDC tooling and know exactly which machine sent the request. No passwords, no API keys, no certificates to rotate.

## Why tsiam

Managing secrets across infrastructure is painful. Static API keys get leaked, certificates are hard to manage securely and expire, and rotation processes are fragile. tsiam replaces all of that with short-lived identity tokens.

Because tsiam uses your Tailscale network membership as the proof of identity, there are no credentials to hand out in the first place. Only machines that are on your Tailnet and have been granted access can get a token.

## How it works

1. tsiam runs as a small service on your Tailscale network.
2. Any machine on the Tailnet sends a `POST /token` request specifying the audience it needs.
3. tsiam checks the caller's Tailscale identity and ACL capabilities, then issues a signed JWT.
4. The application presents that JWT to the target service, which validates it via the OIDC discovery endpoints tsiam exposes.

The token encodes the caller's Tailscale node identity and nothing else — no user passwords, no shared secrets.

Key benefits:

- **Zero-credential authentication**: Applications authenticate using their Tailscale identity, without secrets to rotate or leak
- **Standard JWT tokens**: Works with any system that supports JWT/OIDC verification
- **Tailscale-native security**: Token requests are only accepted from authenticated Tailscale nodes
- **Public key verification**: Expose JWKS endpoints via Tailscale Funnel so external services can verify tokens
- **Flexible key storage**: Store signing keys locally, in memory, or securely in Azure Key Vault

## Works with

tsiam tokens are standard JWTs and work anywhere that supports JWT or OIDC token validation.

- **AWS IAM** via OIDC identity provider federation
- **Microsoft Entra ID (Azure AD)** via Workload Identity Federation
- **Google Cloud IAM** via Workload Identity Pool providers
- **Any service** that accepts a Bearer token and can verify a JWT signature

## tsiam vs tsidp

Tailscale's own [tsidp](https://pkg.go.dev/tailscale.com/tsidp) is an OIDC identity provider, designed for **human authentication**. A solution leverages tsidp so that users can log in using their Tailscale identity.

tsiam is designed for **workload/machine identity**: it issues short-lived JWT assertion tokens on behalf of a Tailscale *node* (a machine), which the workload then exchanges for credentials with cloud providers (AWS, Azure, GCP) or other services via workload identity federation. This is comparable to AWS IAM roles, Azure Managed Identity / Workload Identity, GitHub Actions identity federation, etc. The subject is the node's Tailscale identity, not a human user.

## Start here

- [Quickstart](/docs/quickstart)
- [Getting a token](/docs/getting-a-token)
- [Configuration](/docs/configuration)
- [What is workload identity?](/concepts/workload-identity)
