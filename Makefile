# Rowsafe agent and CLI: build, test and release.
#
#   make build                 host binaries into bin/
#   make test                  unit tests
#   make lint                  go vet, gofmt, shellcheck, installer consistency
#   make test-installer        scripts/install.sh in Debian/Ubuntu containers (Docker)
#   make test-rewind           a real Rewind (copy, rows, in place, undo) on a systemd Debian container (Docker)
#   make dist VERSION=1.2.3 RELEASE_PUBLIC_KEY=...    reproducible release binaries in dist/1.2.3/
#   make release VERSION=1.2.3 RELEASE_PUBLIC_KEY=... (needs ROWSAFE_RELEASE_PRIVATE_KEY)
#                              dist + Ed25519-signed manifest + rendered install.sh + SHA256SUMS
#
# Release builds are reproducible: CGO off, -trimpath, no VCS stamping, no
# build ID, the Go toolchain pinned in go.mod. Rebuilding a tag with the same
# VERSION and RELEASE_PUBLIC_KEY gives byte-identical binaries (see
# docs/verifying-releases.md).

SHELL := /bin/sh
GO ?= go
PKG := github.com/rowsafe/rowsafe

VERSION ?= dev
RELEASE_PUBLIC_KEY ?=
RELEASE_BASE_URL ?= https://releases.rowsafe.sh/agent

DIST := dist/$(VERSION)
AGENT_LDFLAGS := -s -w -buildid= -X $(PKG)/internal/agent.Version=$(VERSION) -X $(PKG)/internal/agent.ReleasePublicKey=$(RELEASE_PUBLIC_KEY)
MAIN_LDFLAGS := -s -w -buildid= -X main.version=$(VERSION)
GOBUILD := CGO_ENABLED=0 GOFLAGS=-mod=readonly $(GO) build -trimpath -buildvcs=false

.PHONY: all build test lint check-installer test-installer test-rewind dist release check-release-env clean

all: lint test build

build:
	$(GOBUILD) -ldflags '$(MAIN_LDFLAGS)' -o bin/rowsafe ./cmd/rowsafe
	$(GOBUILD) -ldflags '$(AGENT_LDFLAGS)' -o bin/rowsafe-agent ./cmd/rowsafe-agent
	$(GOBUILD) -ldflags '$(MAIN_LDFLAGS)' -o bin/rowsafe-release ./cmd/rowsafe-release

test:
	$(GO) test ./...

lint: check-installer
	$(GO) vet ./...
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	@if command -v shellcheck >/dev/null 2>&1; then \
		shellcheck -S warning -s sh scripts/install.sh scripts/test-install.sh scripts/test-rewind.sh scripts/rowsafe-agent-guard scripts/rowsafe-pg-restart; \
	else echo "shellcheck not installed; skipping"; fi

# install.sh is fetched on its own with curl, so it embeds the guard, the
# systemd units, the restart helper and the logrotate config; they must stay
# identical to the files in the repository.
check-installer:
	@sed -n "/<<'ROWSAFE_GUARD_EOF'; then\$$/,/^ROWSAFE_GUARD_EOF\$$/p" scripts/install.sh | sed '1d;$$d' | \
		diff -u scripts/rowsafe-agent-guard - || { echo "scripts/install.sh: embedded guard differs from scripts/rowsafe-agent-guard"; exit 1; }
	@sed -n "/<<'ROWSAFE_UNIT_EOF'; then\$$/,/^ROWSAFE_UNIT_EOF\$$/p" scripts/install.sh | sed '1d;$$d' | \
		diff -u deploy/systemd/rowsafe-agent.service - || { echo "scripts/install.sh: embedded unit differs from deploy/systemd/rowsafe-agent.service"; exit 1; }
	@sed -n "/<<'ROWSAFE_LOGROTATE_EOF' || true\$$/,/^ROWSAFE_LOGROTATE_EOF\$$/p" scripts/install.sh | sed '1d;$$d' | \
		diff -u deploy/logrotate/rowsafe - || { echo "scripts/install.sh: embedded logrotate config differs from deploy/logrotate/rowsafe"; exit 1; }
	@sed -n "/<<'ROWSAFE_RESTART_HELPER_EOF'; then\$$/,/^ROWSAFE_RESTART_HELPER_EOF\$$/p" scripts/install.sh | sed '1d;$$d' | \
		diff -u scripts/rowsafe-pg-restart - || { echo "scripts/install.sh: embedded restart helper differs from scripts/rowsafe-pg-restart"; exit 1; }
	@sed -n "/<<'ROWSAFE_RESTART_SERVICE_EOF'; then\$$/,/^ROWSAFE_RESTART_SERVICE_EOF\$$/p" scripts/install.sh | sed '1d;$$d' | \
		diff -u deploy/systemd/rowsafe-pg-restart.service - || { echo "scripts/install.sh: embedded unit differs from deploy/systemd/rowsafe-pg-restart.service"; exit 1; }
	@sed -n "/<<'ROWSAFE_RESTART_PATH_EOF'; then\$$/,/^ROWSAFE_RESTART_PATH_EOF\$$/p" scripts/install.sh | sed '1d;$$d' | \
		diff -u deploy/systemd/rowsafe-pg-restart.path - || { echo "scripts/install.sh: embedded unit differs from deploy/systemd/rowsafe-pg-restart.path"; exit 1; }
	@sh -n scripts/install.sh

test-installer:
	sh scripts/test-install.sh

test-rewind:
	sh scripts/test-rewind.sh

# The agent ships for linux/amd64 and linux/arm64 (the names the release
# manifest expects); the CLI and the release tool for Linux and macOS.
dist:
	@rm -rf $(DIST) && mkdir -p $(DIST)
	@for arch in amd64 arm64; do \
		echo "rowsafe-agent linux/$$arch"; \
		GOOS=linux GOARCH=$$arch $(GOBUILD) -ldflags '$(AGENT_LDFLAGS)' -o $(DIST)/rowsafe-agent-linux-$$arch ./cmd/rowsafe-agent || exit 1; \
	done
	@for os in linux darwin; do for arch in amd64 arm64; do \
		echo "rowsafe, rowsafe-release $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch $(GOBUILD) -ldflags '$(MAIN_LDFLAGS)' -o $(DIST)/rowsafe-$$os-$$arch ./cmd/rowsafe || exit 1; \
		GOOS=$$os GOARCH=$$arch $(GOBUILD) -ldflags '$(MAIN_LDFLAGS)' -o $(DIST)/rowsafe-release-$$os-$$arch ./cmd/rowsafe-release || exit 1; \
	done; done

check-release-env:
	@echo "$(VERSION)" | grep -Eq '^[0-9]+\.[0-9]+\.[0-9]+$$' || \
		{ echo "VERSION must be MAJOR.MINOR.PATCH (got '$(VERSION)')" >&2; exit 1; }
	@test -n "$(RELEASE_PUBLIC_KEY)" || \
		{ echo "RELEASE_PUBLIC_KEY is not set: agents built without it can never self-update" >&2; exit 1; }
	@test -n "$$ROWSAFE_RELEASE_PRIVATE_KEY" || \
		{ echo "ROWSAFE_RELEASE_PRIVATE_KEY is not set in the environment" >&2; exit 1; }

# A release is immutable once published: agents and the installer verify the
# manifest signature with the public key compiled into them, and never
# downgrade. The private key never leaves the protected release environment.
release: check-release-env
	$(MAKE) dist VERSION=$(VERSION) RELEASE_PUBLIC_KEY=$(RELEASE_PUBLIC_KEY)
	$(GOBUILD) -ldflags '$(MAIN_LDFLAGS)' -o bin/rowsafe-release ./cmd/rowsafe-release
	bin/rowsafe-release manifest --version $(VERSION) --base-url $(RELEASE_BASE_URL) --dist $(DIST) > $(DIST)/manifest.json
	bin/rowsafe-release sign --key-env ROWSAFE_RELEASE_PRIVATE_KEY $(DIST)/manifest.json
	bin/rowsafe-release verify --public-key '$(RELEASE_PUBLIC_KEY)' $(DIST)/manifest.json $(DIST)/manifest.json.sig
	sed 's|@RELEASE_PUBLIC_KEY@|$(RELEASE_PUBLIC_KEY)|' scripts/install.sh > $(DIST)/install.sh
	@grep -q '@RELEASE_PUBLIC_KEY@' $(DIST)/install.sh && { echo "install.sh was not rendered" >&2; exit 1; } || true
	cd $(DIST) && if command -v sha256sum >/dev/null 2>&1; then sha256sum -- * > SHA256SUMS; else shasum -a 256 -- * > SHA256SUMS; fi

clean:
	rm -rf bin dist
