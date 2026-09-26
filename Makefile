# Vora Probe
#
# Local development targets. Release automation lives in
# .github/workflows/release.yml; the image target here is for a local container
# runtime and is not part of the release path.

MODULE  := github.com/vorash/vora-probe
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GO      ?= go

BINARIES := vora-probe vora-probe-worker
PLATFORMS := linux/amd64 linux/arm64

.PHONY: help
help:
	@echo "make check          format check, vet and tests (offline), including the lab workload"
	@echo "make test           tests only"
	@echo "make build          build both binaries into bin/"
	@echo "make release        cross-compile release archives into dist/"
	@echo "make image          build the worker image locally (needs podman or docker)"
	@echo "make replay FIXTURE=test/fixtures/oom/oom-positive   investigate a fixture"
	@echo "make evaluate       compare evaluators (model arms report as blocked without endpoints)"

.PHONY: check
check: fmt-check vet test lab-test

.PHONY: fmt-check
fmt-check:
	@out=$$(gofmt -l . | grep -v '^$$' || true); \
	if [ -n "$$out" ]; then echo "gofmt needed:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet:
	$(GO) vet ./...

.PHONY: test
test:
	$(GO) test ./...

# The lab workload is its own module, so ./... from the root does not reach it.
.PHONY: lab-test
lab-test:
	cd deploy/lab/memory-test && $(GO) vet ./... && $(GO) test ./...

.PHONY: build
build:
	@mkdir -p bin
	@for b in $(BINARIES); do \
		$(GO) build -trimpath -ldflags "-s -w" -o bin/$$b ./cmd/$$b; \
		echo "built bin/$$b"; \
	done

.PHONY: release
release:
	@rm -rf dist && mkdir -p dist
	@for platform in $(PLATFORMS); do \
		os=$${platform%/*}; arch=$${platform#*/}; \
		for b in $(BINARIES); do \
			GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" \
				-o dist/$$b ./cmd/$$b || exit 1; \
			tar -C dist -czf dist/$$b-$(VERSION)-$$os-$$arch.tar.gz $$b; \
			rm -f dist/$$b; \
		done; \
	done
	@cd dist && sha256sum *.tar.gz > checksums.txt && cat checksums.txt

.PHONY: replay
replay:
	$(GO) run ./cmd/vora-probe replay $(FIXTURE) --out .probe

.PHONY: evaluate
evaluate:
	$(GO) run ./cmd/vora-probe evaluate --out .probe/evaluation --loop

.PHONY: image
image:
	podman build -f Dockerfile.worker -t vora-probe-worker:$(VERSION) .
