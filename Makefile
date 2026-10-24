CLANG ?= clang
LLVM_PATH ?= /opt/homebrew/opt/llvm/bin

# Include LLVM tools in PATH if available
ifneq ($(wildcard $(LLVM_PATH)/clang),)
	export PATH := $(LLVM_PATH):$(PATH)
endif

.PHONY: all generate build test validate clean

all: generate build

generate:
	go generate ./...

build:
	CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o bin/imds-canary ./cmd/imds-canary

test:
	go test -v ./...

validate: build
	./scripts/validate.sh

clean:
	rm -rf bin/
