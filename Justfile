
# Show what's available instead of forcing everyone to read the Justfile.
[private]
default:
	just -l

# Run the test suite.
[group('test')]
test:
	ginkgo --randomize-all --randomize-suites --fail-on-pending -trace -race --show-node-events -r

# Keep every pinned dependency (Go, nix, sysdig-cli-scanner) current in one go.
[group('update')]
update: update-cli-scanner update-oldest-cli-scanner
	nix flake update
	nix develop --command go get -u -t -v ./...
	nix develop --command go mod tidy
	nix develop --command just rehash-package-nix

# (internal) Print the latest published sysdig-cli-scanner version
[group('update')]
[private]
_latest-version:
	@curl -sL https://download.sysdig.com/scanning/sysdig-cli-scanner/latest_version.txt | tr -d '[:space:]'

# Find the oldest sysdig-cli-scanner version still within the support window (default 365 days)
[group('update')]
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
# appears. Markers are HTML-comment spans in Markdown and trailing `#`/`//`
# comments in YAML/TS. Target files are discovered, not hardcoded, so a new
# marker anywhere is picked up automatically. DO NOT delete those markers.
[group('update')]
[private]
_set-version marker version:
	#!/usr/bin/env bash
	set -euo pipefail
	# Discover files carrying this marker. Skip the tooling/docs that only name
	# the marker in prose.
	mapfile -t files < <(grep -rl \
	    --exclude-dir=.git \
	    --exclude=justfile --exclude=Justfile \
	    --exclude=AGENTS.md --exclude=CLAUDE.md \
	    "{{marker}}-version-marker" . | sort)
	if [ "${#files[@]}" -eq 0 ]; then
	    echo "No files found carrying {{marker}}-version-marker" >&2
	    exit 1
	fi
	for f in "${files[@]}"; do
	    echo "Updating $f" >&2
	    # Markdown: <!-- {{marker}}-version-marker ... -->X<!-- /{{marker}}-version-marker -->
	    sed -i -E "s#(<!-- {{marker}}-version-marker[^>]*-->)[0-9][0-9.]*(<!-- /{{marker}}-version-marker -->)#\1{{version}}\2#g" "$f"
	    # YAML/TS: line carrying a `#`/`//` {{marker}}-version-marker comment
	    sed -i -E "/(#|\/\/)[[:space:]]*{{marker}}-version-marker/ s/[0-9]+\.[0-9]+\.[0-9]+/{{version}}/" "$f"
	done

# Substitute the oldest supported version wherever the oldest-version-marker is placed
[group('update')]
update-oldest-cli-scanner window_days="365":
	#!/usr/bin/env bash
	set -euo pipefail
	oldest=$(just oldest-cli-scanner {{window_days}})
	just _set-version oldest "$oldest"
	echo "Oldest supported version set to $oldest (via oldest-version-marker)"

# Update sysdig-cli-scanner default to the latest available version
[group('update')]
update-cli-scanner:
	#!/usr/bin/env bash
	set -euo pipefail
	latest=$(just _latest-version)
	just _set-version newest "$latest"
	echo "Newest (default) version set to $latest (via newest-version-marker)"

# Keep package.nix's vendorHash in sync after Go dependencies change.
[group('update')]
rehash-package-nix:
	sd 'vendorHash = ".*";' 'vendorHash = "";' package.nix; h="$((nix build -L --no-link .#harbor-adapter || true) 2>&1 | sed -nE 's/.*got:[[:space:]]+([^ ]+).*/\1/p' | tail -1)"; [ -n "$h" ] && sd 'vendorHash = ".*";' "vendorHash = \"$h\";" package.nix && echo "vendorHash -> $h"

# Everything that must pass before opening/merging a PR.
[group('validate')]
check: lint check-vulns test

# Make sure no dependency has a known vulnerability.
[group('validate')]
check-vulns:
	govulncheck -show=verbose -test ./...

# Enforce code quality and style rules.
[group('validate')]
lint:
	golangci-lint run

# Keep code formatting consistent across the repo.
[group('utils')]
fmt:
	go fmt ./...
	gofumpt -w ./
