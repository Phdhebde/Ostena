#!/usr/bin/env bash
# Démonstration de bout en bout du jalon M1 (docs/demo-m1.md).
#
# Avec le binaire `ostena` et des processus locaux, sans Docker :
#   1. cérémonie de la racine et clés du core ;
#   2. PostgreSQL, core en mode production ;
#   3. agent enrôlé, serveur SSH de l'agent ;
#   4. cible : un vrai sshd OpenSSH dans un espace de noms réseau (netns et
#      veth), car le contrôle de périmètre refuse la boucle locale et les
#      adresses de l'hôte ; ou une cible externe donnée (voir plus bas) ;
#   5. inventaire, mot de passe et TOTP d'alice ;
#   6. `ostena login` (mot de passe et TOTP), puis
#      `ssh <compte>@srv-demo@bastion.demo` : le core vérifie le droit et
#      émet un grant, l'agent ouvre la session vers la cible ;
#   7. transcript écrit et scellé dans la chaîne d'audit ;
#   8. `ostena audit verify` : chaîne et transcripts intacts (code 0) ;
#   9. altérations détectées (code 1) : un transcript modifié (AUD-E018),
#      supprimé (AUD-E017), un octet de l'export changé, l'enregistrement
#      transcript.sealed modifié dans la base (AUD-E007).
#
# Usage : lab/demo-m1.sh
#
# Variables :
#   OSTENA_BIN          binaire à utiliser (défaut : target/release/ostena,
#                       construit s'il manque)
#   OSTENA_TOTP_CODE    générateur de codes TOTP (défaut : l'exemple
#                       totp_code d'ostena-crypto, construit s'il manque)
#   OSTENA_DEMO_DIR     dossier de travail (défaut : un dossier temporaire,
#                       supprimé à la fin sauf avec OSTENA_DEMO_KEEP=1)
#   OSTENA_DEMO_DB_SOCKET, OSTENA_DEMO_DB_USER
#                       PostgreSQL 16 par socket Unix et `peer` (défaut :
#                       /var/run/postgresql et l'utilisateur courant ; le
#                       rôle doit avoir CREATEDB et CREATEROLE : il joue
#                       le superutilisateur de `ostena core db init`)
#   Cible externe, si aucun netns n'est possible (pas de `ip` ou pas de
#   droits) :
#   OSTENA_DEMO_TARGET           hôte:port, pas une adresse de cet hôte
#   OSTENA_DEMO_TARGET_USER      compte sur la cible
#   OSTENA_DEMO_TARGET_HOST_KEY  fichier de la clé d'hôte ECDSA P-256 de la
#                                cible (ligne `ecdsa-sha2-nistp256 AAAA…`)
#   OSTENA_DEMO_AGENT_ADDR       adresse de cet hôte vue par la cible ; la
#                                ligne `authorized_keys` à déposer sur la
#                                cible est affichée, et le script attend
#                                qu'elle soit déposée (Entrée)
#
# Codes de sortie : 0 démonstration réussie, 1 une étape a échoué.
set -euo pipefail

repo="$(cd "$(dirname "$0")/.." && pwd)"
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO="sudo"

step_no=0
step_title=""
step() {
  step_no=$((step_no + 1))
  step_title="$*"
  printf '\n\033[1m== %s. %s\033[0m\n' "$step_no" "$*"
}
info() { printf '   %s\n' "$*"; }
ok() {
  printf '   \033[32mok\033[0m  %s\n' "$*"
  printf '| %s. %s | %s |\n' "$step_no" "$step_title" "$*" >> "$work/results.md"
}
die() { printf '\n\033[31mÉCHEC\033[0m %s\n' "$*" >&2; exit 1; }

# --- Dossier de travail et nettoyage -------------------------------------
work="${OSTENA_DEMO_DIR:-$(mktemp -d "${TMPDIR:-/tmp}/ostena-demo-m1.XXXXXX")}"
mkdir -p "$work"
chmod 700 "$work"
ns="ostena-demo-$$"
db="ostena_demo_$$"
pids=()
netns_made=""
db_made=""
cleanup() {
  status=$?
  for pid in "${pids[@]}"; do kill "$pid" 2>/dev/null || true; done
  if [ -f "$work/target/sshd.pid" ]; then
    $SUDO kill "$(cat "$work/target/sshd.pid")" 2>/dev/null || true
  fi
  if [ -n "$netns_made" ]; then
    $SUDO ip link del ostena-d0 2>/dev/null || true
    $SUDO ip netns del "$ns" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
  if [ -n "$db_made" ]; then
    # The database belongs to ostena_owner (ostena core db init).
    psql -h "$db_socket" -U "$db_user" -d postgres -q -c "SET ROLE ostena_owner" \
      -c "DROP DATABASE IF EXISTS \"$db\" WITH (FORCE)" 2>/dev/null || true
  fi
  if [ "$status" -ne 0 ]; then
    for log in core agent; do
      if [ -f "$work/$log.log" ]; then
        printf '\n--- fin du journal %s ---\n' "$log" >&2
        tail -n 25 "$work/$log.log" >&2
      fi
    done
  fi
  if [ "${OSTENA_DEMO_KEEP:-}" = "1" ] || [ -n "${OSTENA_DEMO_DIR:-}" ]; then
    printf '\nDossier conservé : %s\n' "$work"
  else
    rm -rf "$work"
  fi
}
trap cleanup EXIT

# --- Outils --------------------------------------------------------------
for tool in ssh ssh-keygen psql; do
  command -v "$tool" >/dev/null || die "outil absent : $tool"
done
sshd_bin="$(command -v sshd || echo /usr/sbin/sshd)"

bin="${OSTENA_BIN:-$repo/target/release/ostena}"
if [ ! -x "$bin" ]; then
  info "construction de $bin"
  (cd "$repo" && cargo build --release --locked -p ostena-cli)
fi
totp="${OSTENA_TOTP_CODE:-$repo/target/debug/examples/totp_code}"
if [ ! -x "$totp" ]; then
  info "construction du générateur TOTP (exemple d'ostena-crypto)"
  (cd "$repo" && cargo build --locked -p ostena-crypto --example totp_code)
fi
ostena() { "$bin" "$@"; }

db_socket="${OSTENA_DEMO_DB_SOCKET:-/var/run/postgresql}"
db_user="${OSTENA_DEMO_DB_USER:-$(id -un)}"

# Ports : tunnel et enrôlement (UDP), connexion (TCP), serveur SSH de l'agent.
tunnel_port="${OSTENA_DEMO_TUNNEL_PORT:-18443}"
enroll_port="${OSTENA_DEMO_ENROLL_PORT:-18444}"
login_port="${OSTENA_DEMO_LOGIN_PORT:-18445}"
ssh_port="${OSTENA_DEMO_SSH_PORT:-12222}"

# Attend une ligne contenant $2 dans le journal $1 (30 s).
wait_log() {
  local log="$1" needle="$2" i
  for i in $(seq 1 300); do
    grep -q -- "$needle" "$log" 2>/dev/null && return 0
    sleep 0.1
  done
  die "« $needle » attendu dans $(basename "$log")"
}

# Lance `ostena verify …` et contrôle son code de sortie et un motif.
expect_verify() {
  local want="$1" pattern="$2"; shift 2
  local out code=0
  out="$(ostena audit verify "$@" 2>&1)" || code=$?
  printf '%s\n' "$out" | sed 's/^/      /'
  [ "$code" -eq "$want" ] || die "code de sortie $code, $want attendu"
  if [ -n "$pattern" ]; then
    printf '%s\n' "$out" | grep -q -- "$pattern" || die "« $pattern » attendu dans le rapport"
  fi
  local found
  found="$(printf '%s\n' "$out" | grep -o 'AUD-[EW][0-9]*' | sort -u | paste -sd, - || true)"
  ok "code de sortie $code${found:+ ($found)}"
}

# La cible : externe, ou dans un netns créé à l'étape 4.
if [ -n "${OSTENA_DEMO_TARGET:-}" ]; then
  target_host="${OSTENA_DEMO_TARGET%:*}"
  target_port="${OSTENA_DEMO_TARGET##*:}"
  target_user="${OSTENA_DEMO_TARGET_USER:?OSTENA_DEMO_TARGET_USER}"
  agent_addr="${OSTENA_DEMO_AGENT_ADDR:?OSTENA_DEMO_AGENT_ADDR}"
  network="$target_host/32"
else
  command -v ip >/dev/null \
    || die "ip (iproute2) absent : installez-le, ou donnez une cible externe (OSTENA_DEMO_TARGET)"
  target_host=10.77.0.2
  target_port=2022
  agent_addr=10.77.0.1
  network=10.77.0.0/24
  target_user="$(id -un)"
fi

echo "Ostena, démonstration M1 : $("$bin" --version)"
echo "Dossier de travail : $work"

# --- 1. PKI ----------------------------------------------------------------
step "Cérémonie de la racine et clés du core (ostena ca)"
mkdir -p "$work/ceremony" "$work/credentials" "$work/agent" "$work/transcripts"
chmod 700 "$work/credentials" "$work/transcripts"
(
  cd "$work/ceremony"
  ostena ca root init --name "Ostena demo" --out media1 --out media2 > root-init.txt
  grep 'Dépositaire' root-init.txt | head -n 2 | sed 's/.*: //' > shares.txt
  echo >> shares.txt
  ostena ca key new --key-out "$work/credentials/server.key" --public-out server.pub > /dev/null
  ostena ca server sign --root media1 --public-key server.pub --name 127.0.0.1 \
    --out "$work/server.pem" < shares.txt > /dev/null 2>&1
  ostena ca key new --key-out "$work/credentials/issuing.key" --public-out issuing.pub > /dev/null
  ostena ca issuing sign --root media1 --public-key issuing.pub --name "Ostena demo issuing" \
    --out "$work/issuing.pem" < shares.txt > /dev/null 2>&1
  cp media1/root.pem "$work/root.pem"
)
for key in grant audit user_ca host_ca; do
  ostena ca key new --key-out "$work/credentials/$key.key" --public-out "$work/$key.pub" > /dev/null
done
ostena ca key new-mac --out "$work/credentials/mac.key" > /dev/null
ostena ca key new-mac --out "$work/credentials/totp.key" > /dev/null
cp "$work/root.pem" "$work/agent/root.pem"
ok "racine hors ligne (2 parts sur 3), certificats du core, clés en credentials"
info "clé publique d'audit pour l'auditeur : $work/audit.pub"

# --- 2. Core ---------------------------------------------------------------
step "PostgreSQL et core en mode production"
cat > "$work/core.toml" <<EOF
mode = "production"

[core]
tunnel_listen = "127.0.0.1:$tunnel_port"
enrollment_listen = "127.0.0.1:$enroll_port"
tls_root_ca = "$work/root.pem"
tls_certificate = "$work/server.pem"
tls_private_key = { credential = "server.key" }
issuing_certificate = "$work/issuing.pem"
issuing_private_key = { credential = "issuing.key" }
grant_signing_key = { credential = "grant.key" }

[core.ssh]
user_ca_key = { credential = "user_ca.key" }
host_ca_key = { credential = "host_ca.key" }
command_mac_key = { credential = "mac.key" }
transcripts_dir = "$work/transcripts"

[core.login]
listen = "127.0.0.1:$login_port"
totp_key = { credential = "totp.key" }
ssh_hosts = ["bastion.demo"]
ssh_port = $ssh_port

[core.audit]
signing_key = { credential = "audit.key" }
head_interval_secs = 1
heartbeat_secs = 60

[core.database]
socket_dir = "$db_socket"
name = "$db"
user = "$db_user"
# The demonstration runs under one system account: it plays the
# administration account too (core.database_role_weak in the log).
migration_user = "$db_user"
EOF
core() { ostena core "$@" --config "$work/core.toml"; }
# Roles and database (ADR-0011), then the schema, as the owner role.
core db init --superuser "$db_user" > /dev/null
db_made=1
core migrate > /dev/null
CREDENTIALS_DIRECTORY="$work/credentials" "$bin" core run --config "$work/core.toml" \
  > "$work/core.log" 2>&1 &
pids+=($!)
wait_log "$work/core.log" core.started
ok "core démarré (journal : core.log)"

# --- 3. Agent --------------------------------------------------------------
step "Agent passerelle : enrôlement et serveur SSH"
group_id="$(cat /proc/sys/kernel/random/uuid)"
core group add demo --id "$group_id" --host-name bastion.demo > /dev/null
core agent token --group "$group_id" --out "$work/token" > /dev/null
wait_log "$work/core.log" enroll.listener_opened
cat > "$work/agent/ostena.toml" <<EOF
mode = "production"

[agent]
gateway_group = "$group_id"
core_address = "127.0.0.1:$tunnel_port"
enrollment_address = "127.0.0.1:$enroll_port"
tls_certificate = "$work/agent/agent.crt"
tls_private_key = "$work/agent/agent.key"
tls_core_ca = "$work/agent/root.pem"
replay_journal = "$work/agent/replay.journal"
shutdown_grace_secs = 2
control_endpoint = "$work/agent/run/agent.sock"

# Plafond local : la politique poussée par le core ne peut pas l'élargir.
[[agent.scope.allow]]
networks = ["$network"]
ports = ["$target_port"]

[agent.ssh]
listen = ["127.0.0.1:$ssh_port"]
EOF
ostena agent enroll --timeout 10 --config "$work/agent/ostena.toml" --token-file "$work/token" > /dev/null
"$bin" agent run --config "$work/agent/ostena.toml" > "$work/agent.log" 2>&1 &
pids+=($!)
wait_log "$work/agent.log" agent.core_connected
ok "agent enrôlé et connecté (journal : agent.log), groupe « demo »"

# --- 4. Cible --------------------------------------------------------------
step "Cible SSH"
if [ -n "${OSTENA_DEMO_TARGET:-}" ]; then
  cp "${OSTENA_DEMO_TARGET_HOST_KEY:?OSTENA_DEMO_TARGET_HOST_KEY}" "$work/target_host.pub"
  info "cible externe : $target_user@$target_host:$target_port"
else
  $SUDO ip netns add "$ns"
  netns_made=1
  $SUDO ip link add ostena-d0 type veth peer name ostena-d1
  $SUDO ip link set ostena-d1 netns "$ns"
  $SUDO ip addr add "$agent_addr/24" dev ostena-d0
  $SUDO ip link set ostena-d0 up
  $SUDO ip netns exec "$ns" ip addr add "$target_host/24" dev ostena-d1
  $SUDO ip netns exec "$ns" ip link set ostena-d1 up
  $SUDO ip netns exec "$ns" ip link set lo up
  mkdir -p "$work/target"
  ssh-keygen -q -t ecdsa -b 256 -N "" -C target -f "$work/target/ssh_host_ecdsa_key"
  cp "$work/target/ssh_host_ecdsa_key.pub" "$work/target_host.pub"
  touch "$work/target/authorized_keys"
  cat > "$work/target/sshd_config" <<EOF
ListenAddress $target_host:$target_port
HostKey $work/target/ssh_host_ecdsa_key
PidFile $work/target/sshd.pid
AuthorizedKeysFile $work/target/authorized_keys
# Fichiers de démonstration hors du dossier personnel.
StrictModes no
PubkeyAuthentication yes
PasswordAuthentication no
KbdInteractiveAuthentication no
UsePAM no
AllowUsers $target_user
LogLevel VERBOSE
EOF
  # sshd tourne sous le compte cible (root en conteneur, l'utilisateur du
  # runner en CI) ; en root, il lui faut son répertoire de séparation.
  [ "$target_user" != root ] || mkdir -p /run/sshd
  $SUDO ip netns exec "$ns" ${SUDO:+sudo -u "$target_user"} "$sshd_bin" \
    -f "$work/target/sshd_config" -E "$work/target/sshd.log"
  for _ in $(seq 1 50); do [ -f "$work/target/sshd.pid" ] && break; sleep 0.1; done
  [ -f "$work/target/sshd.pid" ] || die "sshd de la cible n'a pas démarré : $(cat "$work/target/sshd.log" 2>/dev/null)"
  info "netns $ns : agent $agent_addr, cible $target_host:$target_port, sshd $("$sshd_bin" -V 2>&1 | head -n 1)"
fi
wait_log "$work/agent.log" agent.ssh_identity_ready
line="$(ostena agent ssh-key --config "$work/agent/ostena.toml" --from "$agent_addr" --line)"
if [ -n "${OSTENA_DEMO_TARGET:-}" ]; then
  info "ligne à déposer dans authorized_keys de $target_user sur la cible :"
  info "$line"
  read -r -p "   Entrée une fois la ligne déposée… " _
else
  printf '%s\n' "$line" > "$work/target/authorized_keys"
fi
ok "clé de l'agent déposée : ${line%% ecdsa*} …"

# --- 5. Inventaire ----------------------------------------------------------
step "Inventaire, droit et identifiants d'alice"
printf '[[allow]]\nnetworks = ["%s"]\nports = ["%s"]\n' "$network" "$target_port" > "$work/policy.toml"
core group policy demo "$work/policy.toml" > /dev/null
wait_log "$work/agent.log" agent.policy_applied
core user add alice --display-name "Alice Martin" > /dev/null
core resource add srv-demo --host "$target_host" --port "$target_port" --group demo \
  --host-key "$work/target_host.pub" > /dev/null
core account add --resource srv-demo "$target_user" > /dev/null
core right grant --user alice --resource srv-demo --account "$target_user" --days 1 \
  --max-session-mins 30 > /dev/null
password="mot de passe de démonstration"
printf '%s\n' "$password" | core user set-password alice --stdin > /dev/null
enrol="$(CREDENTIALS_DIRECTORY="$work/credentials" ostena core user totp-enroll alice --config "$work/core.toml")"
secret="$(printf '%s\n' "$enrol" | sed -n 's/^ *clé : //p')"
[ -n "$secret" ] || die "secret TOTP non affiché"
printf '%s\n' "$secret" > "$work/alice.totp"
chmod 600 "$work/alice.totp"
"$totp" < "$work/alice.totp" \
  | CREDENTIALS_DIRECTORY="$work/credentials" ostena core user totp-enroll alice --confirm --stdin \
      --config "$work/core.toml" > /dev/null
core user list | sed 's/^/      /'
ok "alice : droit sur $target_user@srv-demo, mot de passe et TOTP confirmés"

# --- 6. Connexion et session SSH --------------------------------------------
step "ostena login (mot de passe et TOTP), puis ssh $target_user@srv-demo@bastion.demo"
# Le code de confirmation est consommé : le pas suivant, accepté à ±30 s.
code="$("$totp" --offset 1 < "$work/alice.totp")"
printf '%s\n%s\n' "$password" "$code" \
  | ostena login --core "127.0.0.1:$login_port" --root "$work/root.pem" --user alice \
      --dir "$work/alice" --stdin | sed 's/^/      /'
wait_log "$work/core.log" login.succeeded
# Le nom du bastion ne résout pas ici : il désigne 127.0.0.1. HostKeyAlias
# garde le nom bastion.demo pour vérifier le certificat d'hôte ; la ligne
# @cert-authority écrite par ostena login vaut pour [bastion.demo]:PORT,
# elle est reprise ici pour le seul nom, sans port, que voit HostKeyAlias.
sed "s/^@cert-authority [^ ]* /@cert-authority bastion.demo /" "$work/alice/known_hosts" \
  > "$work/known_hosts.demo"
cat > "$work/ssh_config" <<EOF
Host bastion.demo
    HostName 127.0.0.1
    HostKeyAlias bastion.demo
    UserKnownHostsFile $work/known_hosts.demo
    BatchMode yes
Include "$work/alice/ssh_config"
EOF
start=$(date +%s%N)
output="$(ssh ${OSTENA_DEMO_SSH_OPTS:-} -F "$work/ssh_config" "$target_user@srv-demo@bastion.demo" \
  'echo ostena-demo-m1; echo "compte : $(id -un)"; uname -n')" || die "session SSH refusée"
elapsed_ms=$(( ($(date +%s%N) - start) / 1000000 ))
printf '%s\n' "$output" | sed 's/^/      /'
printf '%s\n' "$output" | grep -q '^ostena-demo-m1$' || die "sortie de la session inattendue"
wait_log "$work/core.log" access.ssh_granted
ok "session ouverte par l'agent vers la cible, connexion et commande en ${elapsed_ms} ms (objectif < 5 s)"
echo "$elapsed_ms" > "$work/session-ms"

# --- 7. Transcript scellé ----------------------------------------------------
step "Transcript écrit et scellé"
wait_log "$work/core.log" transcript.sealed
cast="$(ls "$work"/transcripts/*.cast)"
[ "$(printf '%s\n' "$cast" | wc -l)" -eq 1 ] || die "un transcript attendu"
info "$(basename "$cast") ($(stat -c '%a' "$cast"), $(stat -c '%s' "$cast") octets) :"
sed 's/^/      /' "$cast"
grep -q 'ostena-demo-m1' "$cast" || die "la sortie de la session manque dans le transcript"
for event in access.ssh_granted access.session_opened access.ssh_exec transcript.sealed; do
  grep -q "$event" "$work/core.log" || die "événement $event absent du journal du core"
done
ok "access.ssh_granted, access.session_opened, access.ssh_exec, transcript.sealed"

# --- 8. Vérification ---------------------------------------------------------
step "Export de l'audit et vérification hors ligne"
core audit head > "$work/head-kept.txt"
info "tête conservée hors du bastion : $(cut -c1-60 "$work/head-kept.txt")…"
# Une tête signée toutes les secondes : réexporter jusqu'à ce qu'elle couvre
# la fin de la chaîne.
for attempt in $(seq 1 20); do
  export_file="$work/audit-$attempt.ostaud"
  core audit export --out "$export_file" > /dev/null
  cp -r "$work/transcripts" "$work/transcripts-copy-$attempt"
  code=0
  ostena audit verify "$export_file" --key "$work/audit.pub" --head "$work/head-kept.txt" \
    --transcripts "$work/transcripts-copy-$attempt" > /dev/null || code=$?
  [ "$code" -eq 0 ] && break
  sleep 0.5
done
copy="$work/transcripts-copy-$attempt"
expect_verify 0 "" "$export_file" --key "$work/audit.pub" --head "$work/head-kept.txt" --transcripts "$copy"

# --- 9. Altérations ----------------------------------------------------------
step "Altération d'un transcript"
tampered="$work/transcripts-tampered"
cp -r "$copy" "$tampered"
chmod -R u+w "$tampered"
sed -i 's/ostena-demo-m1/ostena-demo-m2/' "$tampered/$(basename "$cast")"
expect_verify 1 AUD-E018 "$export_file" --key "$work/audit.pub" --transcripts "$tampered"
rm "$tampered/$(basename "$cast")"
expect_verify 1 AUD-E017 "$export_file" --key "$work/audit.pub" --transcripts "$tampered"

step "Altération du fichier d'export"
cp "$export_file" "$work/export-tampered.ostaud"
size=$(stat -c '%s' "$work/export-tampered.ostaud")
printf '\xff' | dd of="$work/export-tampered.ostaud" bs=1 seek=$((size / 2)) conv=notrunc status=none
expect_verify 1 "AUD-E0" "$work/export-tampered.ostaud" --key "$work/audit.pub"

step "Altération dans la base (propriétaire du schéma, déclencheurs désactivés)"
seq_sealed="$(psql -h "$db_socket" -U "$db_user" -d "$db" -tA -q -c "SET ROLE ostena_owner" \
  -c "SELECT seq FROM audit_record WHERE event = 'transcript.sealed' ORDER BY seq LIMIT 1")"
info "enregistrement transcript.sealed : seq $seq_sealed"
psql -h "$db_socket" -U "$db_user" -d "$db" -q -v ON_ERROR_STOP=1 <<EOF
SET ROLE ostena_owner;
ALTER TABLE audit_record DISABLE TRIGGER USER;
UPDATE audit_record SET body = overlay(body placing '\xff'::bytea from 80 for 1) WHERE seq = $seq_sealed;
ALTER TABLE audit_record ENABLE TRIGGER USER;
EOF
core audit export --out "$work/audit-after-edit.ostaud" > /dev/null
expect_verify 1 AUD-E007 "$work/audit-after-edit.ostaud" --key "$work/audit.pub" --head "$work/head-kept.txt"

printf '\n\033[1mDémonstration M1 réussie.\033[0m Session en %s ms.\n' "$elapsed_ms"
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  {
    echo "## Démonstration M1 (lab/demo-m1.sh)"
    echo
    echo "Binaire : \`$("$bin" --version)\`. Session SSH établie et commande exécutée en ${elapsed_ms} ms."
    echo
    echo "| Étape | Résultat |"
    echo "|---|---|"
    sed 's/`//g' "$work/results.md"
  } >> "$GITHUB_STEP_SUMMARY"
fi
