#!/usr/bin/env sh
# Creates a smart link and shows how it routes different visitors.
set -eu
BASE=${BASE_URL:-http://localhost:8080}
TOKEN=${ADMIN_TOKEN:-$(grep -E '^ADMIN_TOKEN=' .env 2>/dev/null | cut -d= -f2-)}
CODE=demo-$(date +%s)

curl -sS -X POST "$BASE/api/links" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{
    \"url\": \"https://example.com\",
    \"code\": \"$CODE\",
    \"fallback_url\": \"https://example.org\",
    \"rules\": {
      \"rules\": [
        {\"name\": \"ios\",     \"when\": {\"devices\": [\"ios\"]},     \"target\": \"https://www.apple.com/app-store/\"},
        {\"name\": \"android\", \"when\": {\"devices\": [\"android\"]}, \"target\": \"https://play.google.com/store\"},
        {\"name\": \"turkey\",  \"when\": {\"countries\": [\"TR\"]},    \"target\": \"https://example.com/tr\"}
      ],
      \"variants\": [
        {\"url\": \"https://example.com/?v=a\", \"weight\": 50},
        {\"url\": \"https://example.com/?v=b\", \"weight\": 50}
      ]
    }
  }"
echo

show() {
  label=$1; shift
  printf '%-9s -> ' "$label"
  curl -sS -o /dev/null -D - "$@" "$BASE/$CODE" | awk 'tolower($1)=="location:"{l=$2} tolower($1)=="x-shrinkit-reason:"{r=$2} END{gsub(/\r/,"",l); gsub(/\r/,"",r); print l "  (" r ")"}'
}
show iPhone   -A 'Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X)'
show Android  -A 'Mozilla/5.0 (Linux; Android 14; Pixel 8)'
show Turkey   -A 'Mozilla/5.0 (Windows NT 10.0)' -H 'CF-IPCountry: TR'
show Desktop1 -A 'Mozilla/5.0 (Windows NT 10.0) visitor-1'
show Desktop2 -A 'Mozilla/5.0 (Macintosh) visitor-2'
echo "Preview page: $BASE/$CODE/preview"
echo "Stats:        curl -H 'Authorization: Bearer $TOKEN' $BASE/api/links/$CODE/stats"
