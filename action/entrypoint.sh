#!/usr/bin/env bash
set -euo pipefail

echo "=== Release Guardian Action (v1 scaffold) ==="

# GitHub provides these env vars in Actions runtime
: "${GITHUB_EVENT_PATH:?Missing GITHUB_EVENT_PATH}"
: "${GITHUB_REPOSITORY:?Missing GITHUB_REPOSITORY}"
: "${GITHUB_SHA:?Missing GITHUB_SHA}"
: "${GITHUB_API_URL:=https://api.github.com}"

# Inputs come via env (GitHub Action convention)
: "${INPUT_GITHUB_TOKEN:?Missing input github_token}"

MODE="${INPUT_MODE:-enforce}"
SEVERITY_THRESHOLD="${INPUT_SEVERITY_THRESHOLD:-high}"
ALLOW_CONDITIONAL="${INPUT_ALLOW_CONDITIONAL:-true}"

REPORT_DIR="${GITHUB_WORKSPACE:-/github/workspace}/.rg"
mkdir -p "${REPORT_DIR}"

REPORT_JSON="${REPORT_DIR}/report.json"
REPORT_MD="${REPORT_DIR}/comment.md"

# Git safety: container UID may not match mounted workspace ownership
git config --global --add safe.directory /github/workspace || true

echo "Event path: ${GITHUB_EVENT_PATH}"
echo "Repo: ${GITHUB_REPOSITORY}"
echo "SHA: ${GITHUB_SHA}"
echo "Mode: ${MODE} | Threshold: ${SEVERITY_THRESHOLD} | Allow conditional: ${ALLOW_CONDITIONAL}"

# Run the python engine (currently placeholder decision)
python -m rg.main \
  --event-path "${GITHUB_EVENT_PATH}" \
  --repo "${GITHUB_REPOSITORY}" \
  --sha "${GITHUB_SHA}" \
  --mode "${MODE}" \
  --severity-threshold "${SEVERITY_THRESHOLD}" \
  --allow-conditional "${ALLOW_CONDITIONAL}" \
  --out-json "${REPORT_JSON}" \
  --out-md "${REPORT_MD}"

# Extract fields
VERDICT="$(jq -r '.verdict' "${REPORT_JSON}")"
RDI_SCORE="$(jq -r '.rdi_score' "${REPORT_JSON}")"
SUMMARY="$(jq -r '.summary' "${REPORT_JSON}")"
PR_NUMBER="$(jq -r '.context.pr_number // empty' "${REPORT_JSON}")"

echo "Verdict: ${VERDICT} | RDI: ${RDI_SCORE} | Summary: ${SUMMARY}"
echo "PR: ${PR_NUMBER:-<none>}"

# Map verdict -> GitHub commit status state
STATUS_STATE="success"
if [[ "${VERDICT}" == "conditional" ]]; then
  STATUS_STATE="error"
elif [[ "${VERDICT}" == "no-go" ]]; then
  STATUS_STATE="failure"
fi

STATUS_CONTEXT="release-guardian/rdi"
STATUS_DESC="${SUMMARY}"
STATUS_TARGET_URL=""

# Set commit status
echo "Setting commit status..."
curl -sS -X POST \
  -H "Authorization: Bearer ${INPUT_GITHUB_TOKEN}" \
  -H "Accept: application/vnd.github+json" \
  "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/statuses/${GITHUB_SHA}" \
  -d "$(jq -nc \
    --arg state "${STATUS_STATE}" \
    --arg context "${STATUS_CONTEXT}" \
    --arg description "${STATUS_DESC}" \
    --arg target_url "${STATUS_TARGET_URL}" \
    '{state:$state, context:$context, description:$description, target_url:$target_url}')" >/dev/null

# Post PR comment (only if pull_request event)
if [[ -n "${PR_NUMBER}" ]]; then
  echo "Upserting PR comment..."
  COMMENT_BODY="$(cat "${REPORT_MD}")"
  MARKER="<!-- release-guardian:rdi -->"

  # Fetch existing comments (paginate lightly; v1: first 100 is usually enough)
  COMMENTS_JSON="$(curl -sS \
    -H "Authorization: Bearer ${INPUT_GITHUB_TOKEN}" \
    -H "Accept: application/vnd.github+json" \
    "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments?per_page=100")"

  # Find first comment ID containing the marker
  EXISTING_ID="$(echo "${COMMENTS_JSON}" | jq -r --arg m "${MARKER}" '
    map(select(.body != null and (.body | contains($m)))) | .[0].id // empty
  ')"

  if [[ -n "${EXISTING_ID}" ]]; then
    echo "Found existing Release Guardian comment (id=${EXISTING_ID}); updating..."
    curl -sS -X PATCH \
      -H "Authorization: Bearer ${INPUT_GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/issues/comments/${EXISTING_ID}" \
      -d "$(jq -nc --arg body "${COMMENT_BODY}" '{body:$body}')" >/dev/null
  else
    echo "No existing Release Guardian comment found; creating..."
    curl -sS -X POST \
      -H "Authorization: Bearer ${INPUT_GITHUB_TOKEN}" \
      -H "Accept: application/vnd.github+json" \
      "${GITHUB_API_URL}/repos/${GITHUB_REPOSITORY}/issues/${PR_NUMBER}/comments" \
      -d "$(jq -nc --arg body "${COMMENT_BODY}" '{body:$body}')" >/dev/null
  fi
else
  echo "Not a pull_request event; skipping PR comment."
fi

# Set action outputs (new GitHub Actions style via $GITHUB_OUTPUT)
if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
  {
    echo "verdict=${VERDICT}"
    echo "rdi_score=${RDI_SCORE}"
    echo "summary=${SUMMARY}"
    echo "report_path=${REPORT_JSON}"
  } >> "${GITHUB_OUTPUT}"
fi

echo "=== Release Guardian Action complete ==="
