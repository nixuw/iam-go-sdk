# Developer targets. Requires Go 1.26.11 (the version in go.mod).
#
#   make vet    formatting and static checks
#   make unit   unit tests against the local fake issuer (package iamtest)
#   make e2e    end-to-end tests against a real IAM; see docs/e2e.md
#   make check  what a change must pass before it is merged: vet, build, unit
GO ?= go

.PHONY: vet fmt build unit e2e check

# gofmt must print nothing; go vet must pass. The e2e package is behind a
# build tag and is vetted as well.
vet:
	@test -z "$$(gofmt -l .)" || { echo "gofmt needed:"; gofmt -l .; exit 1; }
	$(GO) vet ./...
	$(GO) vet -tags e2e ./e2e/...

fmt:
	gofmt -w .

# The SDK uses no cgo and must build with the flags of the standard image.
build:
	CGO_ENABLED=0 $(GO) build -trimpath ./...

unit:
	$(GO) test -race -count=1 ./...

# IAM_E2E_FIXTURE names a JSON file that describes a real IAM and the
# applications registered in it for this run. docs/e2e.md explains the file
# and how the IAM project produces it for its own interoperability run.
e2e:
	@test -n "$(IAM_E2E_FIXTURE)" || { echo "IAM_E2E_FIXTURE is not set; see docs/e2e.md"; exit 1; }
	IAM_E2E_FIXTURE='$(IAM_E2E_FIXTURE)' $(GO) test -tags e2e -count=1 -v ./e2e/...

check: vet build unit
