#!/usr/bin/env bash
# End-to-end tests of the portal (ADR-0020, § 6), against the real binary.
#
# Starts a core in development mode with [core.web] on localhost, a PKI made
# by `ostena ca`, a fresh PostgreSQL database, and one user (password and
# TOTP) per test and browser; then runs Playwright in portal/e2e/. Fails if the
# core logged a CSP report (web.csp_report).
#
# Usage : tests/portal/e2e.sh [arguments de playwright test]
#   e.g. tests/portal/e2e.sh --project chromium
#
# Variables :
#   OSTENA_BIN             binaire (défaut : target/debug/ostena), qui doit
#                          embarquer le portail (`cargo xtask portal` avant
#                          sa construction)
#   OSTENA_TEST_DB_SOCKET  socket Unix de PostgreSQL 16 (défaut :
#                          /var/run/postgresql), authentification peer
#   OSTENA_TEST_DB_USER    rôle de test (CREATEDB, CREATEROLE), qui joue le
#                          service et les migrations (mode development)
#   OSTENA_E2E_PORT        port du portail (défaut : 18446)
#   OSTENA_E2E_KEEP=1      conserve le dossier de travail
#
# Prérequis : node, et `npm ci` fait dans portal/e2e/ (Playwright et ses
# navigateurs : `npx playwright install`, jamais dans le build hors ligne).
set -euo pipefail

repo="$(cd "$(dirname "$0")/../.." && pwd)"
bin="${OSTENA_BIN:-$repo/target/debug/ostena}"
db_socket="${OSTENA_TEST_DB_SOCKET:-/var/run/postgresql}"
db_user="${OSTENA_TEST_DB_USER:?OSTENA_TEST_DB_USER (rôle de test de PostgreSQL)}"
port="${OSTENA_E2E_PORT:-18446}"
origin="https://localhost:$port"

die() { printf 'ÉCHEC %s\n' "$*" >&2; exit 1; }
[ -x "$bin" ] || die "binaire absent : $bin"
[ -d "$repo/portal/e2e/node_modules/@playwright/test" ] || die "npm ci absent dans portal/e2e/"
"$bin" core portal-manifest > /dev/null || die "ce binaire n'embarque pas le portail"

work="$(mktemp -d "${TMPDIR:-/tmp}/ostena-e2e.XXXXXX")"
chmod 700 "$work"
db="ostena_e2e_$$"
core_pid=""
db_made=""
cleanup() {
  status=$?
  [ -z "$core_pid" ] || kill "$core_pid" 2>/dev/null || true
  wait 2>/dev/null || true
  if [ -n "$db_made" ]; then
    psql -h "$db_socket" -U "$db_user" -d postgres -q \
      -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)" > /dev/null 2>&1 || true
  fi
  if [ "$status" -ne 0 ] && [ -f "$work/core.log" ]; then
    printf '\n--- fin du journal du core ---\n' >&2
    tail -n 30 "$work/core.log" >&2
  fi
  if [ "${OSTENA_E2E_KEEP:-}" = "1" ]; then
    printf 'Dossier conservé : %s\n' "$work"
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT

wait_log() {
  local i
  for i in $(seq 1 300); do
    grep -q -- "$1" "$work/core.log" 2>/dev/null && return 0
    kill -0 "$core_pid" 2>/dev/null || die "le core s'est arrêté"
    sleep 0.1
  done
  die "« $1 » attendu dans le journal du core"
}

# PKI: an offline root (2 shares of 3), the core's certificate for
# localhost, its issuing CA and its service keys, in credentials.
mkdir -p "$work/ceremony" "$work/credentials"
chmod 700 "$work/credentials"
(
  cd "$work/ceremony"
  "$bin" ca root init --name "Ostena e2e" --out media1 --out media2 > root-init.txt
  grep 'Dépositaire' root-init.txt | head -n 2 | sed 's/.*: //' > shares.txt
  echo >> shares.txt
  "$bin" ca key new --key-out "$work/credentials/server.key" --public-out server.pub > /dev/null
  "$bin" ca server sign --root media1 --public-key server.pub --name localhost \
    --out "$work/server.pem" < shares.txt > /dev/null 2>&1
  "$bin" ca key new --key-out "$work/credentials/issuing.key" --public-out issuing.pub > /dev/null
  "$bin" ca issuing sign --root media1 --public-key issuing.pub --name "Ostena e2e issuing" \
    --out "$work/issuing.pem" < shares.txt > /dev/null 2>&1
  cp media1/root.pem "$work/root.pem"
)
for key in grant audit user_ca host_ca; do
  "$bin" ca key new --key-out "$work/credentials/$key.key" --public-out "$work/$key.pub" > /dev/null
done
"$bin" ca key new-mac --out "$work/credentials/totp.key" > /dev/null
"$bin" ca key new-mac --out "$work/credentials/mac.key" > /dev/null
mkdir -m 700 "$work/transcripts"

# Free ports next to the portal's for the other listeners.
cat > "$work/core.toml" <<EOF
mode = "development"

[core]
tunnel_listen = "127.0.0.1:$((port + 1))"
enrollment_listen = "127.0.0.1:$((port + 2))"
tls_root_ca = "$work/root.pem"
tls_certificate = "$work/server.pem"
tls_private_key = { credential = "server.key" }
issuing_certificate = "$work/issuing.pem"
issuing_private_key = { credential = "issuing.key" }
grant_signing_key = { credential = "grant.key" }

# [core.login] requires it: the user CA signs the session certificates.
[core.ssh]
user_ca_key = { credential = "user_ca.key" }
host_ca_key = { credential = "host_ca.key" }
command_mac_key = { credential = "mac.key" }
transcripts_dir = "$work/transcripts"

[core.login]
listen = "127.0.0.1:$((port + 3))"
totp_key = { credential = "totp.key" }
ssh_hosts = ["bastion.e2e"]
# Both browsers and their workers log in from 127.0.0.1.
attempts_per_minute = 120

[core.web]
listen = "127.0.0.1:$port"
origin = "$origin"

[core.audit]
signing_key = { credential = "audit.key" }
# The runners cannot make files append-only (CAP_LINUX_IMMUTABLE):
# tolerated in development, refused in production (CFG-P024).
worm = "disabled"

[core.database]
socket_dir = "$db_socket"
name = "$db"
user = "$db_user"
migration_user = "$db_user"
EOF
core() { CREDENTIALS_DIRECTORY="$work/credentials" "$bin" core "$@" --config "$work/core.toml"; }

core db init --superuser "$db_user" > /dev/null
db_made=1
core migrate > /dev/null
# Not through the function: $! must be the core itself, for the cleanup.
CREDENTIALS_DIRECTORY="$work/credentials" "$bin" core run --config "$work/core.toml" \
  > "$work/core.log" 2>&1 &
core_pid=$!
wait_log web.listener_started

# One user per test and browser: a TOTP step is accepted once per user.
users="$work/users.json"
printf '[' > "$users"
sep=""
for project in chromium firefox; do
  for slot in 1 2 3; do
    name="e2e-$project-$slot"
    password="mot de passe e2e $slot $RANDOM$RANDOM"
    core user add "$name" --display-name "E2E $project $slot" > /dev/null
    printf '%s\n' "$password" | core user set-password "$name" --stdin > /dev/null
    secret="$(core user totp-enroll "$name" | sed -n 's/^ *clé : //p')"
    [ -n "$secret" ] || die "secret TOTP non affiché pour $name"
    node "$repo/portal/e2e/tests/totp.mjs" "$secret" \
      | core user totp-enroll "$name" --confirm --stdin > /dev/null
    printf '%s{"name":"%s","password":"%s","secret":"%s"}' "$sep" "$name" "$password" "$secret" >> "$users"
    sep=","
  done
done
printf ']\n' >> "$users"
chmod 600 "$users"

echo "core : $origin (journal : $work/core.log)"
status=0
(
  cd "$repo/portal/e2e"
  OSTENA_E2E_ORIGIN="$origin" OSTENA_E2E_USERS="$users" npx --no-install playwright test "$@"
) || status=$?

# The browsers also report CSP violations to the core.
if grep -q web.csp_report "$work/core.log"; then
  grep web.csp_report "$work/core.log" >&2
  die "rapport CSP reçu par le core"
fi
[ "$status" -eq 0 ] || die "playwright : code $status"
echo "portail de bout en bout : ok"
