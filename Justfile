
[private]
default:
	just -l

test:
	ginkgo --randomize-all --randomize-suites --fail-on-pending -trace -race --show-node-events -r

update:
	nix flake update
	nix develop --command go get -u -t -v ./...
	nix develop --command go mod tidy
	nix develop --command just rehash-package-nix
	nix develop --command just update-cli-scanner
	nix develop --command just update-oldest-cli-scanner

# (internal) Print the latest published sysdig-cli-scanner version
[private]
_latest-version:
	@curl --silent --fail --show-error --location https://download.sysdig.com/scanning/sysdig-cli-scanner/latest_version.txt | tr -d '[:space:]'

# Find the oldest sysdig-cli-scanner version still within the support window (default 365 days)
oldest-cli-scanner window_days="365":
	#!/usr/bin/env bash
	set -euo pipefail
	base="https://download.sysdig.com/scanning/bin/sysdig-cli-scanner"
	os="linux"; arch="amd64"
	cutoff=$(( $(date -u +%s) - {{window_days}} * 86400 ))
	latest=$(just _latest-version)
	major=${latest%%.*}
	minor=$(echo "$latest" | cut -d. -f2)
	oldest_ver=""; oldest_epoch=""
	for m in $(seq "$minor" -1 0); do
		minor_hit=0; misses=0
		for p in $(seq 0 30); do
			v="$major.$m.$p"
			lm=$(curl -sfI "$base/$v/$os/$arch/sysdig-cli-scanner" \
				| grep -i '^last-modified:' | sed 's/^[Ll]ast-[Mm]odified: //' | tr -d '\r' || true)
			if [ -z "$lm" ]; then
				misses=$((misses + 1)); [ "$misses" -ge 2 ] && break; continue
			fi
			misses=0
			epoch=$(date -u -d "$lm" +%s)
			if [ "$epoch" -ge "$cutoff" ]; then
				minor_hit=1
				if [ -z "$oldest_epoch" ] || [ "$epoch" -lt "$oldest_epoch" ]; then
					oldest_epoch=$epoch; oldest_ver=$v
				fi
			fi
		done
		# Versions are chronological: once a whole minor is out of window, stop.
		[ "$minor_hit" -eq 0 ] && [ -n "$oldest_ver" ] && break
	done
	if [ -z "$oldest_ver" ]; then
		echo "No version found within the last {{window_days}} days" >&2
		exit 1
	fi
	echo >&2 "Oldest supported: $oldest_ver (released $(date -u -d "@$oldest_epoch" '+%Y-%m-%d'))"
	echo "$oldest_ver"

# (internal) Replace the version tagged with <marker>-version-marker wherever it
# appears. Markers are trailing `#`/`//` comments in YAML/Go. Target files are
# discovered, not hardcoded, so a new marker anywhere is picked up automatically.
# DO NOT delete those markers.
[private]
_set-version marker version:
	#!/usr/bin/env bash
	set -euo pipefail
	# Discover files carrying this marker. Skip deps, the git dir, and the
	# tooling/docs that only name the marker in prose.
	mapfile -t files < <(grep -rl \
		--exclude-dir=.git --exclude-dir=vendor \
		--exclude='[Jj]ustfile' --exclude=AGENTS.md \
		"{{marker}}-version-marker" . | sort)
	if [ "${#files[@]}" -eq 0 ]; then
		echo "No files found carrying {{marker}}-version-marker" >&2
		exit 1
	fi
	for f in "${files[@]}"; do
		echo "Updating $f" >&2
		sed -i -E "/(#|\/\/)[[:space:]]*{{marker}}-version-marker/ s/[0-9]+\.[0-9]+\.[0-9]+/{{version}}/" "$f"
	done

# Substitute the oldest supported version wherever the oldest-version-marker is placed
update-oldest-cli-scanner window_days="365":
	#!/usr/bin/env bash
	set -euo pipefail
	oldest=$(just oldest-cli-scanner {{window_days}})
	just _set-version oldest "$oldest"
	echo "Oldest supported version set to $oldest (via oldest-version-marker)"

# Substitute the latest version wherever the newest-version-marker is placed
update-cli-scanner:
	#!/usr/bin/env bash
	set -euo pipefail
	latest=$(just _latest-version)
	just _set-version newest "$latest"
	echo "Newest version set to $latest (via newest-version-marker)"

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
