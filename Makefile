.PHONY: test
test:
	go test -tags unit ./...

.PHONY: test-integration
test-integration:
	go test -v -tags integration ./tests/integration/...

.PHONY: test-race
test-race:
	CGO_ENABLED=1 go test -race -tags unit ./...

.PHONY: lint
lint:
	golangci-lint run -c .golangci.yaml

# Scan for known vulnerabilities in code that is reachable from tsiam, for every OS that releases are built for
# The tool is built once for the host and then run with GOOS set, since `GOOS=x go tool` would build govulncheck itself for that OS
.PHONY: vulncheck
vulncheck:
	@set -e; \
	govulncheck=$$(go tool -n govulncheck); \
	for goos in linux windows freebsd; do \
		echo "### govulncheck GOOS=$$goos"; \
		GOOS=$$goos $$govulncheck ./...; \
	done

.PHONY: gen-config
gen-config:
	go tool gen-config

# Ensure gen-config ran
.PHONY: check-config-diff
check-config-diff: gen-config
	git diff --exit-code config.sample.yaml config.md
