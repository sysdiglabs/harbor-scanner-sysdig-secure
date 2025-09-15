
[private]
default:
	just -l

test:
	ginkgo --randomize-all --randomize-suites --fail-on-pending -trace -race --show-node-events -r

bump:
	nix flake update
	nix develop --command go get -u -t -v ./...
	nix develop --command go mod tidy

check: lint check-vulns test

check-vulns:
	govulncheck -show=verbose -test ./...

lint:
	golangci-lint run

fmt:
	go fmt ./...
	gofumpt -w ./
