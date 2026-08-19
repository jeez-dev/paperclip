#!/usr/bin/env bash
# Minimal helper. Usage: paperclip-issue-update.sh --issue-id ID --status DONE <<'MD'
set -euo pipefail
issue_id=""
status=""
while [ $# -gt 0 ]; do
  case "$1" in
    --issue-id) issue_id="$2"; shift 2;;
    --status) status="$2"; shift 2;;
    *) shift;;
  esac
done
body="$(cat)"
payload="$(jq -n --arg s "$status" --arg c "$body" '{status:$s, comment:$c}')"
curl -s -X PATCH \
  -H "Authorization: Bearer $PAPERCLIP_API_KEY" \
  -H "Content-Type: application/json" \
  -H "X-Paperclip-Run-Id: $PAPERCLIP_RUN_ID" \
  -d "$payload" \
  "$PAPERCLIP_API_URL/api/issues/$issue_id" | python3 -c "import json,sys; d=json.load(sys.stdin); print('status:', d.get('status'), '| id:', d.get('identifier'))"
