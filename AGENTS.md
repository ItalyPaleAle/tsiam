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

In tests, never invoke functions inside assertions that check errors, such as `require.Error`, `require.NoError`, `require.ErrorIs`, `assert.ErrorContains`, and similar.
Always assign the result to an `err` variable on a separate line first, then pass the variable to the assertion.
This does not apply to assertions that do not check errors.

```go
// Wrong
require.Error(t, something())

// Wrong
require.ErrorIs(t, something(), context.Canceled)

// Wrong
require.NoError(t, something())

// Right
err := something()
require.Error(t, err)

// Right
err := something()
require.ErrorIs(t, err, context.Canceled)

// Right
err := something()
require.NoError(t, err)
```

If you modify `pkg/config.Config` or any struct referenced from it, always run `make gen-config` before finishing the task.

The Go build tag `unit` is meant for files that contain helpers for unit tests. It should never be included in a Go test file (ending in `_test.go`).

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
```

## Documentation

Be concise.

Write docs for end users, who don't care about internal implementation details.

## Running tests

Always pass `-tags unit` when running Go tests — several test helpers are guarded by that build tag, so tests will fail to compile without it.

When compiling or testing code that imports use Go 1.27+.

```sh
go test -tags unit ./...
```

## Running the linter

The linter is pinned to a specific version (included in `.golangci-lint-version`), which must be installed from the pre-compiled binary: builds from package managers are compiled with an older Go and refuse this module's Go version.

```sh
VERSION="2.x.x" # From .golangci-lint-version
curl -sSL https://github.com/golangci/golangci-lint/releases/download/v${VERSION}/golangci-lint-${VERSION}-linux-amd64.tar.gz | tar -xz -C /tmp
install /tmp/golangci-lint-${VERSION}-linux-amd64/golangci-lint /usr/local/bin
make lint
```

## Git

Do not stage or unstage changes unless the user explicitly asks you to.

### Commit messages

Write the subject line in the imperative mood, without a trailing period, following the conventional commit prefixes. For example:

- `feat:` for new features
- `fix:` for bug fixes
- `fix(sec):` for security-related fixes
- `refactor:` for refactorings
- `docs:` for docs-only changes

The prefix is followed by a lowercase summary

When a commit does more than one thing, list the changes in the body as a numbered list, one line each, without trailing periods.
Describe what changes for users, and leave out refactors and test-only changes.

If the commit breaks something for users, end the body with a paragraph that starts with `**Breaking**:`, says what breaks, and what users need to do.

```text
fix(sec): harden ssh-agent and published PEM keys

1. ssh-agent signs only SSH logins and git signatures for its key
2. Backups are written with mode 0600

**Breaking**: ssh-agent refuses to sign anything other than SSH logins and git signatures, and its --note is limited to 66 characters
```
