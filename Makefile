MODULE := github.com/raphbaph/CompliantAI
VERSION ?= dev
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || printf unknown)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X '$(MODULE)/internal/version.Version=$(VERSION)' \
	-X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/version.BuildTime=$(BUILD_TIME)'

.PHONY: test test-race vet build

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

build:
	go build -trimpath -ldflags "$(LDFLAGS)" ./cmd/...
