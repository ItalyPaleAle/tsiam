# Coding Style Guidelines

## Go

Never define variables inside `if` conditions. Always declare variables on a separate line before the conditional check.

```go
// Wrong
if err := something(); err != nil { ... }

// Wrong
if val, ok := something.(string); ok { ... }

// Right
err := something()
if err != nil { ... }

// Right
val, ok := something.(string)
if ok { ... }
```

If you modify `pkg/config.Config` or any struct referenced from it, always run `make gen-config` before finishing the task.

## Running tests

When compiling or testing code that imports use Go 1.27+.

## Running the linter

The linter is pinned to a specific version (included in `.github/workflows/ci.yaml`), which must be installed from the pre-compiled binary: builds from package managers are compiled with an older Go and refuse this module's Go version.

```sh
VERSION="2.x.x" # From .github/workflows/ci.yaml
curl -sSL https://github.com/golangci/golangci-lint/releases/download/v${VERSION}/golangci-lint-${VERSION}-linux-amd64.tar.gz | tar -xz -C /tmp
install /tmp/golangci-lint-${VERSION}-linux-amd64/golangci-lint /usr/local/bin
make lint
```

## Comments

- One sentence per line; do not wrap to a max line length
- No trailing period on single-line comments
- Prefer comments that explain intent, invariants, or why a branch exists
- Avoid comments that simply restate the next line of code
- For multi-step logic, use short section comments to separate the steps and explain why each step exists

```go
// Wrong — wrapped mid-sentence
// This function performs the main validation logic. It checks
// the input against the schema and returns an error if the
// input is invalid.

// Wrong — trailing period on single-line comment
// Validate the input.

// Right
// This function performs the main validation logic
// It checks the input against the schema and returns an error if the input is invalid

// Right
// Validate the input

// Right
// Normalize the request host so callers can pass either Host or X-Forwarded-Host values

// Right
// Browsers do not accept a cookie Domain attribute set to an IP address
// Returning an empty domain tells the caller to set a host-only cookie instead

// Wrong — restates the code
// Trim whitespace and lowercase the host
host = strings.TrimSpace(strings.ToLower(host))
```

## Git

Do not stage or unstage changes unless the user explicitly asks you to.
