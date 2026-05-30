---
title: "Audience Authorization"
weight: 40
---

tsiam implements a two-layer authorization model that controls which JWT audiences can be requested and by which machines.

## Layer 1: Global allowlist

The global allowlist defines every audience that any node on the Tailnet is ever permitted to request. Any audience not in this list will be rejected regardless of who is asking.

Configure it in `config.yaml`:

```yaml
tokens:
  allowedAudiences:
    - "https://api.example.com"
    - "https://database.internal"
    - "api://AzureADTokenExchange"   # Microsoft Entra ID workload identity
    - "sts.amazonaws.com"            # AWS IAM federation
```

This is a required field: tsiam will not start without at least one entry.

## Layer 2: Per-node ACL capabilities

The global allowlist is a service-level boundary, but it doesn't differentiate between callers. For fine-grained control, use [Tailscale ACL capabilities](https://tailscale.com/kb/1324/acl-capabilities) to specify exactly which nodes can request which audiences.

Add a grant to your Tailscale ACL policy using the capability key `italypaleale.me/tsiam`:

```json
{
  "grants": [
    {
      "src": ["tag:webserver"],
      "dst": ["tag:tsiam"],
      "app": {
        "italypaleale.me/tsiam": [
          {
            "allowedAudiences": [
              "https://api.example.com"
            ]
          }
        ]
      }
    },
    {
      "src": ["tag:backend"],
      "dst": ["tag:tsiam"],
      "app": {
        "italypaleale.me/tsiam": [
          {
            "allowedAudiences": [
              "https://api.example.com",
              "sts.amazonaws.com"
            ]
          }
        ]
      }
    }
  ]
}
```

In this example:

- Nodes tagged `tag:webserver` can only request tokens for `https://api.example.com`
- Nodes tagged `tag:backend` can request tokens for both `https://api.example.com` and `sts.amazonaws.com`
- The tsiam service node must be tagged `tag:tsiam`

## Shared workload identity via `subject`

If multiple nodes should share a single workload identity (for example, a fleet of identical worker machines), add a `subject` field to their capability grants and set `tokens.subjectClaim: capability` in your config:

```json
{
  "grants": [
    {
      "src": ["tag:worker"],
      "dst": ["tag:tsiam"],
      "app": {
        "italypaleale.me/tsiam": [
          {
            "allowedAudiences": ["sts.amazonaws.com"],
            "subject": "worker-fleet"
          }
        ]
      }
    }
  ]
}
```

```yaml
tokens:
  subjectClaim: capability
```

All nodes tagged `tag:worker` will receive tokens with `"sub": "worker-fleet"`, regardless of their individual node IDs. This lets you bind a single IAM role or trust policy to the entire fleet.

## Nodes without capabilities

By default, a node that has no matching ACL capability grant cannot request any audience. The request is rejected even if the audience is in the global allowlist.

To allow nodes without capabilities to request any globally-allowed audience, set:

```yaml
tokens:
  allowEmptyNodeCapability: true
```

**Security recommendation:** Keep `allowEmptyNodeCapability: false` (the default) and explicitly grant capabilities to each node or tag. This provides defense in depth, making sure that nodes are not requesting tokens for services they shouldn't have access to.
