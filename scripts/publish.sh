#!/usr/bin/env bash
#
# Publish all rTime workspace crates to crates.io in dependency order,
# handling crates.io's new-crate rate limit (HTTP 429) gracefully.
#
# - Publishes in dependency order: rtime-core first, its dependents next,
#   and the `rtimed` binary crate last.
# - Idempotent: any crate already published at the current version is skipped,
#   so it is safe to re-run after a partial or rate-limited publish.
# - On a 429, it waits until the reset time crates.io reports (falling back to
#   a fixed delay) and then retries the same crate.
#
# Usage:
#   scripts/publish.sh              # publish
#   scripts/publish.sh --dry-run    # verify packaging without uploading
#
# Env:
#   RATE_LIMIT_SLEEP   Fallback wait (seconds) after a 429 when the reset time
#                      cannot be parsed. Default: 645 (crates.io refills roughly
#                      one new-crate token every 10 minutes).
#
set -euo pipefail

DRY_RUN=""
if [[ "${1:-}" == "--dry-run" ]]; then
  DRY_RUN="--dry-run"
fi

# Dependency order. rtime-refclock has no dependents here; rtimed depends on the
# rest and must come last.
CRATES=(
  rtime-core
  rtime-clock
  rtime-net
  rtime-ntp
  rtime-nts
  rtime-ptp
  rtime-refclock
  rtime-metrics
  rtimed
)

RATE_LIMIT_SLEEP="${RATE_LIMIT_SLEEP:-645}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repo_root"

version="$(grep -m1 -E '^version = "' Cargo.toml | sed -E 's/.*"([^"]+)".*/\1/')"
if [[ -z "$version" ]]; then
  echo "!! could not determine workspace version from Cargo.toml" >&2
  exit 1
fi
echo ">> rTime publish — version ${version}${DRY_RUN:+ (dry run)}"

# Returns 0 if <crate> <version> is already on crates.io.
already_published() {
  local crate="$1"
  curl -sf "https://crates.io/api/v1/crates/${crate}/${version}" \
    -A "rtime-publish-script (${crate})" 2>/dev/null \
    | grep -q "\"num\":\"${version}\""
}

# Seconds to sleep after a 429, honoring the reset time in the cargo error if we
# can parse it, otherwise falling back to RATE_LIMIT_SLEEP.
rate_limit_wait() {
  local log="$1" reset target now wait
  reset="$(grep -oiE 'try again after [A-Za-z0-9:, ]+GMT' "$log" | head -1 | sed -E 's/.*try again after //I')"
  if [[ -n "$reset" ]] && target="$(date -u -d "$reset" +%s 2>/dev/null)"; then
    now="$(date -u +%s)"
    wait=$(( target - now + 10 ))
    (( wait < 5 )) && wait=5
  else
    wait="$RATE_LIMIT_SLEEP"
  fi
  echo "$wait"
}

for crate in "${CRATES[@]}"; do
  if [[ -z "$DRY_RUN" ]] && already_published "$crate"; then
    echo ">> ${crate} ${version} already on crates.io — skipping"
    continue
  fi

  attempt=0
  while true; do
    attempt=$(( attempt + 1 ))
    echo ">> [$(date -u '+%H:%M:%SZ')] publishing ${crate} (attempt ${attempt})"
    log="$(mktemp)"
    if cargo publish -p "$crate" $DRY_RUN 2>&1 | tee "$log"; then
      echo ">> ${crate} done"
      rm -f "$log"
      break
    fi
    if grep -qiE 'already (exists|uploaded)|already .* uploaded' "$log"; then
      echo ">> ${crate} already published — continuing"
      rm -f "$log"
      break
    elif grep -qiE '429|too many requests|rate.?limit' "$log"; then
      wait="$(rate_limit_wait "$log")"
      echo ">> [$(date -u '+%H:%M:%SZ')] rate limited — waiting ${wait}s before retrying ${crate}"
      rm -f "$log"
      sleep "$wait"
    else
      echo "!! hard error publishing ${crate} — aborting" >&2
      rm -f "$log"
      exit 1
    fi
  done
done

echo ">> All rTime crates published at ${version}."
