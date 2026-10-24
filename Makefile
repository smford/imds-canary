CLANG ?= clang
LLVM_PATH ?= /opt/homebrew/opt/llvm/bin

# Include LLVM tools in PATH if available
ifneq ($(wildcard $(LLVM_PATH)/clang),)
	export PATH := $(LLVM_PATH):$(PATH)
endif

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "0.1.0")
COMMIT ?= $(shell git rev-parse HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS = -s -w \
	-X github.com/smford/imds-canary/internal/version.Version=$(VERSION) \
	-X github.com/smford/imds-canary/internal/version.Commit=$(COMMIT) \
	-X github.com/smford/imds-canary/internal/version.Date=$(DATE)

.PHONY: all generate build test validate clean

all: generate build

generate:
	go generate ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="$(LDFLAGS)" -o bin/imds-canary ./cmd/imds-canary

test:
	go test -v -race ./...

validate: build
	./scripts/validate.sh

clean:
	rm -rf bin/
