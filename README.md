<p align="center">
  <img src="docs/static/icon-light.svg" alt="Tsiam icon" width="60" height="60" />
</p>

# tsiam - Workload Identity over Tailscale

**[📚 Read the docs](https://tsiam.italypaleale.me)**

A Tailscale-powered workload identity service that provides JWT tokens based on the node identity in the tailnet. Think of it as a Tailscale version of Kubernetes workload identity (using Service Account Tokens), AWS IAM Roles for EC2, Azure Managed Identity.

## ✨ Why tsiam

tsiam lets your applications authenticate themselves based on their Tailscale network identity—no passwords, API keys, or certificates to manage. Any machine on your Tailnet can request a signed JWT token that proves its identity.

- **Zero-credential authentication**: Applications authenticate using their Tailscale identity, without secrets to rotate or leak
- **Standard JWT tokens**: Works with any system that supports JWT/OIDC verification
- **Tailscale-native security**: Token requests are only accepted from authenticated Tailscale nodes
- **Public key verification**: Expose JWKS endpoints via Tailscale Funnel so external services can verify tokens
- **Flexible key storage**: Store signing keys locally, in memory, or securely in Azure Key Vault

### 💡 Use Cases

- Grant access to cloud resources (databases, storage, APIs) based on Tailscale node identity
- Enable service-to-service authentication
- Replace static API keys with short-lived, identity-bound tokens
- Integrate Tailscale identity with existing OIDC-compatible systems
- Build zero-trust architectures where every request is authenticated

## 🔐 tsiam vs tsidp

Tailscale's own [tsidp](https://pkg.go.dev/tailscale.com/tsidp) is an OIDC identity provider, designed for **human authentication**. A solution leverages tsidp so that users can log in using their Tailscale identity.

tsiam is designed for **workload/machine identity**: it issues short-lived JWT assertion tokens on behalf of a Tailscale *node* (a machine), which the workload then exchanges for credentials with cloud providers (AWS, Azure, GCP) or other services via workload identity federation. This is comparable to AWS IAM roles, Azure Managed Identity / Workload Identity, GitHub Actions identity federation, etc. The subject is the node's Tailscale identity, not a human user.

## 📘 Docs

The documentation is available at [`https://tsiam.italypaleale.me`](https://tsiam.italypaleale.me).

- [Quickstart](https://tsiam.italypaleale.me/docs/quickstart)
- [Getting a token](https://tsiam.italypaleale.me/docs/getting-a-token)
- [Configuration](https://tsiam.italypaleale.me/docs/configuration)
- [Audience Authorization](https://tsiam.italypaleale.me/docs/audience-authorization)
- [Tailscale Funnel](https://tsiam.italypaleale.me/docs/tailscale-funnel)
- [What is workload identity?](https://tsiam.italypaleale.me/concepts/workload-identity)

## License

This project is licensed under the MIT License.
