#!/bin/bash
set -euo pipefail


API_BASE="${API_BASE:-https://sekbehf5na.execute-api.us-east-1.amazonaws.com/dev}"
TIMESTAMP=$(date +%s)

CLIENT_EMAIL="client.$TIMESTAMP@example.com"
STAFF_EMAIL="staff.$TIMESTAMP@example.com"
CLIENT_PASS="cliente123"
STAFF_PASS="staff123"

echo
echo "Using API base: $API_BASE"

# Helper to run a curl and show body + HTTP code
run_curl() {
  local method="$1"; shift
  local url="$1"; shift
  local data="$1"; shift || true

  if [ -n "$data" ]; then
    curl -X "$method" "$url" -H "Content-Type: application/json" -d "$data" -w "\nHTTP:%{http_code}\n"
  else
    curl -X "$method" "$url" -H "Content-Type: application/json" -w "\nHTTP:%{http_code}\n"
  fi
}

# 1) Generate invitation code (show response)
echo "\n=== Generate invitation code ==="
INVITE_RESP=$(run_curl POST "$API_BASE/auth/generate-invitation" '{"max_uses":5,"expires_in_days":1,"created_by":"local-test"}')
echo "$INVITE_RESP"

# extract code (jq preferred, sed fallback)
INVITE_CODE=""
if command -v jq &>/dev/null; then
  INVITE_CODE=$(echo "$INVITE_RESP" | jq -r '.invitation_code' 2>/dev/null || true)
fi
if [ -z "$INVITE_CODE" ]; then
  INVITE_CODE=$(echo "$INVITE_RESP" | sed -n 's/.*"invitation_code"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
fi

echo "Invitation code: $INVITE_CODE"

# 2) Register client
echo "\n=== Register client ==="
run_curl POST "$API_BASE/auth/registro" "{\"name\":\"Cliente Test\",\"email\":\"$CLIENT_EMAIL\",\"password\":\"$CLIENT_PASS\",\"phone\":\"123456789\",\"gender\":\"otro\",\"user_type\":\"cliente\",\"frontend_type\":\"client\"}"

# 3) Register staff (using invitation code)
echo "\n=== Register staff (with invite) ==="
run_curl POST "$API_BASE/auth/registro" "{\"name\":\"Staff Test\",\"email\":\"$STAFF_EMAIL\",\"password\":\"$STAFF_PASS\",\"user_type\":\"staff\",\"staff_tier\":\"admin\",\"invitation_code\":\"$INVITE_CODE\",\"frontend_type\":\"staff\"}"

# 4) Negative: register staff without code
echo "\n=== Register staff WITHOUT invite (expected 403) ==="
run_curl POST "$API_BASE/auth/registro" "{\"name\":\"Staff NoCode\",\"email\":\"staff.nocode.$TIMESTAMP@example.com\",\"password\":\"$STAFF_PASS\",\"user_type\":\"staff\",\"staff_tier\":\"admin\",\"frontend_type\":\"staff\"}"

# 5) Negative: register staff with invalid code
echo "\n=== Register staff WITH INVALID invite (expected 403) ==="
run_curl POST "$API_BASE/auth/registro" "{\"name\":\"Staff BadCode\",\"email\":\"staff.badcode.$TIMESTAMP@example.com\",\"password\":\"$STAFF_PASS\",\"user_type\":\"staff\",\"staff_tier\":\"admin\",\"invitation_code\":\"INVALID_CODE_123\",\"frontend_type\":\"staff\"}"

# 6) Duplicate email test (client)
echo "\n=== Duplicate client registration (expected 409) ==="
run_curl POST "$API_BASE/auth/registro" "{\"name\":\"Cliente Duplicado\",\"email\":\"$CLIENT_EMAIL\",\"password\":\"$CLIENT_PASS\",\"user_type\":\"cliente\",\"frontend_type\":\"client\"}"

# 7) Login client and extract token
echo "\n=== Login client ==="
LOGIN_CLIENT_RESP=$(run_curl POST "$API_BASE/auth/login" "{\"email\":\"$CLIENT_EMAIL\",\"password\":\"$CLIENT_PASS\",\"frontend_type\":\"client\"}")
echo "$LOGIN_CLIENT_RESP"
CLIENT_TOKEN=""
if command -v jq &>/dev/null; then
  CLIENT_TOKEN=$(echo "$LOGIN_CLIENT_RESP" | jq -r '.token' 2>/dev/null || true)
fi
if [ -z "$CLIENT_TOKEN" ]; then
  CLIENT_TOKEN=$(echo "$LOGIN_CLIENT_RESP" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
fi

echo "Client token: ${CLIENT_TOKEN:0:40}..."

# 8) Login staff (if earlier registration succeeded)
echo "\n=== Login staff ==="
LOGIN_STAFF_RESP=$(run_curl POST "$API_BASE/auth/login" "{\"email\":\"$STAFF_EMAIL\",\"password\":\"$STAFF_PASS\",\"frontend_type\":\"staff\"}")
echo "$LOGIN_STAFF_RESP"
STAFF_TOKEN=""
if command -v jq &>/dev/null; then
  STAFF_TOKEN=$(echo "$LOGIN_STAFF_RESP" | jq -r '.token' 2>/dev/null || true)
fi
if [ -z "$STAFF_TOKEN" ]; then
  STAFF_TOKEN=$(echo "$LOGIN_STAFF_RESP" | sed -n 's/.*"token"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')
fi

echo "Staff token: ${STAFF_TOKEN:0:40}..."

# 9) Logout (no token)
echo "\n=== Logout (no token) ==="
run_curl POST "$API_BASE/auth/logout" '{}' 

# 10) Logout with client token (if available)
if [ -n "$CLIENT_TOKEN" ]; then
  echo "\n=== Logout with client token ==="
  curl -X POST "$API_BASE/auth/logout" -H "Content-Type: application/json" -H "Authorization: Bearer $CLIENT_TOKEN" -d '{}' -w "\nHTTP:%{http_code}\n"
fi

# 11) Logout with staff token (if available)
if [ -n "$STAFF_TOKEN" ]; then
  echo "\n=== Logout with staff token ==="
  curl -X POST "$API_BASE/auth/logout" -H "Content-Type: application/json" -H "Authorization: Bearer $STAFF_TOKEN" -d '{}' -w "\nHTTP:%{http_code}\n"
fi

echo "\n=== Done ===\n"
