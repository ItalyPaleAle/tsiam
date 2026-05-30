---
title: "What is workload identity?"
nav_title: "Workload Identity"
weight: 10
---

Workload identity helps providing an answer to *how does an app prove who it is?*

Developers are used to managing credentials for applications using things like connection strings, API keys, or certificates: things an app *knows*. These are often saved in config files or passed as environmental variables. However, what they all have in common is that they are shared, long-lived credentials, which are notably hard to manage correctly, can leak in surprising ways, and tend to be rotated only after an incident has already happened. Things get even more complicated as you add the need to have those credentials available in local development environments to.

Workload identity solves this by shifting the question from *what does this process know?* to *what is this process?*. The proof of identity comes from the runtime environment (the platform that the workload runs on) rather than from a secret the workload carries.

## How the major platforms do it

Workload identity is widely adopted throughout the industry, especially in more "cloud native" environments.

### AWS: IAM Roles for EC2 and ECS

When an EC2 instance or ECS task is launched with an IAM role attached, AWS makes temporary credentials available via the [instance metadata service](https://docs.aws.amazon.com/AWSEC2/latest/UserGuide/iam-roles-for-amazon-ec2.html) at `http://169.254.169.254`. The application reads those credentials automatically through the AWS SDK, no secret ever needs to be configured or managed.

The credentials are short-lived and automatically rotated by the platform. The application simply asks "who am I?" and the environment answers.

### Azure: Managed Identity

Azure provides [Managed Identity](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/overview) for VMs, App Services, Container Apps, AKS pods, and more. An application running on a resource with a managed identity can request an access token from the local metadata endpoint (`http://169.254.169.254/metadata/identity/oauth2/token`). The Azure platform handles key management and token signing transparently.

The application never sees a client secret. The identity is tied to the Azure resource, not to any credential stored in the application.

### Kubernetes: Service Account Tokens

Kubernetes [pod identity](https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/) works similarly. Each pod is associated with a service account, and Kubernetes automatically mounts a short-lived token at `/var/run/secrets/kubernetes.io/serviceaccount/token`. Applications can present that token to the Kubernetes API or to external services that trust the cluster's OIDC issuer.

Workload identity federation on AWS ([IRSA](https://docs.aws.amazon.com/eks/latest/userguide/iam-roles-for-service-accounts.html)) and Azure ([AAD Workload Identity](https://azure.github.io/azure-workload-identity/docs/)) extends this pattern: the pod's service account token is exchanged for a cloud provider credential, without any static secrets.

## The common thread

In every case, the pattern is the same:

1. The **platform** (e.g. AWS, Azure, Kubernetes) knows what the workload is and issues a signed token asserting its identity.
2. The **workload** presents that token to whatever service it needs to access.
3. The **service** validates the token by fetching the platform's public keys (via an OIDC discovery endpoint) and checking the signature.

The credentials are short-lived and non-exportable: even if someone intercepted one, it would expire quickly and couldn't be re-created outside the platform.

## tsiam: workload identity for Tailscale networks

tsiam brings the same pattern to your Tailscale network.

Your Tailnet is the platform where apps are running in. Every node on the Tailnet has a verified identity: Tailscale's coordination server issued it a certificate and maintains it as long as the node is authenticated. tsiam leverages that identity proof and issues a signed JWT token on the node's behalf.

The token encodes the node's Tailscale ID, name, IP addresses, and tags. Any service that trusts tsiam's OIDC endpoint can verify it with standard JWT tooling. Because the token request goes over the Tailnet, tsiam knows with certainty who is asking: the caller can't fake their Tailscale identity any more than an EC2 instance can fake its IAM role.

The result is a workload identity system that works for any machine on your Tailnet, including physical servers, VMs, containers, cloud instances, regardless of where they run or which cloud provider hosts them.

## tsiam vs tsidp

It's worth distinguishing tsiam from Tailscale's own [tsidp](https://pkg.go.dev/tailscale.com/tsidp).

**tsidp** is an OIDC identity provider for **humans**. It lets a *user* log in to a web application using their Tailscale identity, similar to "Sign in with Google". The subject of the token is the user.

**tsiam** is an identity provider for **machines/workloads**. It lets a *node* (a process, a container, a server) prove its identity to another service. The subject of the token is the node. No human is involved in the flow.

| | tsidp | tsiam |
|-|-------|-------|
| Subject | Human user | Machine / workload |
| Use case | Web app login, SSO | Service-to-service auth, cloud credential exchange |
| Flow | User opens browser, authenticates | App calls `/token` endpoint |
| Analogous to | "Sign in with Tailscale" | AWS IAM role, Azure Managed Identity, Kubernetes pod identity |

If you need to let users authenticate to services using their Tailscale identity, use tsidp. If you need your applications to authenticate themselves to other services, use tsiam.
