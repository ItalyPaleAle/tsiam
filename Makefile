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

.PHONY: gen-config
gen-config:
	go tool gen-config

# Ensure gen-config ran
.PHONY: check-config-diff
check-config-diff: gen-config
	git diff --exit-code config.sample.yaml config.md
