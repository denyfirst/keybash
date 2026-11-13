#!/bin/sh
# Keep the one issue a scheduled freshness job owns: open it, or add the new
# report to it while it stays open; close it once a run finds nothing.
#   freshness-issue.sh open TITLE REPORT_FILE
#   freshness-issue.sh close TITLE
# Needs gh with GH_TOKEN (issues: write) and GH_REPO. Titles are fixed by the
# workflow; the report is written by Keybash's own checks.
set -eu
action="$1"
title="$2"
run="${GITHUB_SERVER_URL}/${GITHUB_REPOSITORY}/actions/runs/${GITHUB_RUN_ID}"
number="$(gh issue list --state open --limit 100 --json number,title \
  --jq "map(select(.title == \"${title}\")) | .[0].number // empty")"
case "${action}" in
  open)
    body="${RUNNER_TEMP}/keybash-issue.md"
    {
      printf 'Found by the scheduled run %s on %s.\n\n' "${run}" "$(date -u +%F)"
      head -c 60000 "$3"
    } > "${body}"
    if test -n "${number}"; then
      gh issue comment "${number}" --body-file "${body}"
    else
      gh issue create --title "${title}" --body-file "${body}"
    fi
    ;;
  close)
    if test -n "${number}"; then
      gh issue close "${number}" --comment "The scheduled run ${run} on $(date -u +%F) found nothing."
    fi
    ;;
  *)
    echo 'usage: freshness-issue.sh open TITLE REPORT_FILE | close TITLE' >&2
    exit 2
    ;;
esac
