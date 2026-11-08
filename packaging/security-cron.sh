#!/bin/sh
# Trigger the tpmd security workflow from a reliable external scheduler.
#
# GitHub's `schedule` event is best-effort and has been observed delaying this
# repository's workflows by hours (the daily packaging cron arrives five to
# seven hours late). A systemd timer or any cron that can POST here gives the
# hourly guarantee GitHub does not:
#
#   GH_TOKEN=... packaging/security-cron.sh
#
# GH_TOKEN needs `Actions: write` on the repository; the RELEASE_TOKEN used by
# the security workflow already has it. The workflow file must exist on the ref.
set -eu

token=${GH_TOKEN:-${GITHUB_TOKEN:-}}
if [ -z "$token" ]; then
	printf 'security-cron.sh: set GH_TOKEN to a token with Actions: write\n' >&2
	exit 1
fi

owner=${TPMD_REPO_OWNER:-OffworldNexus}
repo=${TPMD_REPO_NAME:-tpmd}
ref=${TPMD_SECURITY_REF:-develop}
workflow=${TPMD_SECURITY_WORKFLOW:-security.yml}

curl -fsS -X POST \
	-H "Authorization: Bearer $token" \
	-H "Accept: application/vnd.github+json" \
	-H "X-GitHub-Api-Version: 2022-11-28" \
	"https://api.github.com/repos/$owner/$repo/actions/workflows/$workflow/dispatches" \
	-d "{\"ref\":\"$ref\"}"
printf 'dispatched %s on %s\n' "$workflow" "$ref"
