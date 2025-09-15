
[private]
default:
	just -l

test:
	ginkgo --randomize-all --randomize-suites --fail-on-pending -trace -race --show-node-events -r

bump:
	nix flake update
	nix develop --command go get -u -t -v ./...
	nix develop --command go mod tidy
	nix develop --command just rehash-package-nix

rehash-package-nix:
	sd 'vendorHash = ".*";' 'vendorHash = "";' package.nix; h="$((nix build -L --no-link .#harbor-adapter || true) 2>&1 | sed -nE 's/.*got:[[:space:]]+([^ ]+).*/\1/p' | tail -1)"; [ -n "$h" ] && sd 'vendorHash = ".*";' "vendorHash = \"$h\";" package.nix && echo "vendorHash -> $h"

check: lint check-vulns test

check-vulns:
	govulncheck -show=verbose -test ./...

lint:
	golangci-lint run

fmt:
	go fmt ./...
	gofumpt -w ./
