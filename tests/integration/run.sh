#!/usr/bin/env bash
# Remote commands are single-quoted on purpose (they expand on the host).
# shellcheck disable=SC2016
# Integration test on throwaway cloud hosts (x86_64 Ubuntu, root SSH).
#
#   run.sh init            generate the lab inventory (inventories/lab, gitignored; vars from lab-vars.yml);
#                          re-run after creating or changing .state/s3.env
#   run.sh deploy          exit pin + tools, site.yml, test VPN client (the stock Xray
#                          client is deployed by the Xray checks that need it)
#   run.sh check [NAME..]  run checks (default: all, in order), print PASS/FAIL
#   run.sh swap            exit swap to EXIT2 (run last), then its checks
#   run.sh swap-entry reachable|unreachable|restore
#                          entry swap to ENTRY2_IP and back (after `swap`)
#   run.sh clean           remove what the test created on the hosts (optional;
#                          the hosts are throwaway and deleted by their owner)
#   run.sh guard           only the prod guard below (every mode but help runs it):
#                          refuse when a lab IP is an ansible_host of inventories/prod
#
# Hosts come from the environment or tests/integration/.state/lab.env:
#   ENTRY_IP, EXIT_IP     entry and exit
#   EXIT2_IP              new exit for the swap test
#   CLIENT_IP             test VPN client host, default EXIT2_IP (else EXIT_IP); best
#                         a host that is not the current exit, so the egress-IP
#                         check discriminates (client_via_exit notes it otherwise)
# S3 (backup checks): tests/integration/.state/s3.env with BACKUP_S3_ENDPOINT,
#   BACKUP_S3_REGION, BACKUP_S3_BUCKET, BACKUP_S3_PREFIX, WRITER_ACCESS_KEY,
#   WRITER_SECRET_KEY, READER_ACCESS_KEY, READER_SECRET_KEY. Without it the
#   inventory gets placeholders and the backup checks are skipped.
# SSH: root with .state/id_ed25519, host keys pinned in .state/known_hosts.
# Logs go to .state/logs/, the PASS/FAIL lines also to .state/results.txt.
set -uo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
# LAB_STATE and PROD_HOSTS are overridable for the guard's tests only.
STATE="${LAB_STATE:-$ROOT/tests/integration/.state}"
PROD_HOSTS="${PROD_HOSTS:-$ROOT/inventories/prod/hosts.yml}"
INV="$ROOT/inventories/lab"
LOGS="$STATE/logs"
RESULTS="$STATE/results.txt"
cd "$ROOT" || exit 1
# shellcheck disable=SC1091
[ -f "$STATE/lab.env" ] && . "$STATE/lab.env"
SSH_KEY="${SSH_KEY:-$STATE/id_ed25519}"
KNOWN_HOSTS="${KNOWN_HOSTS:-$STATE/known_hosts}"
CLIENT_IP="${CLIENT_IP:-${EXIT2_IP:-${EXIT_IP:-}}}"
CLIENT_TUN_IP=10.8.1.2
# The only plays of swap-exit.yml allowed to touch the entry.
SWAP_ENTRY_PLAYS="Point the exit DNS record at the new exit|Wait for the entry to handshake with the new exit|Verify the entry egresses through the exit"
# Reports changed on every run by design (fills the split sets now).
ALWAYS_CHANGED="split_routing : Run the first refresh"
mkdir -p "$LOGS"
export ANSIBLE_VAULT_PASSWORD_FILE="$STATE/vault-pass"

die() { echo "run.sh: $*" >&2; exit 1; }
need() { local v; for v in "$@"; do [ -n "${!v:-}" ] || die "$v is not set (env or $STATE/lab.env)"; done; }
log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*" >&2; }

# The lab must never point at a production host: refuse when any lab IP is an
# ansible_host of the prod inventory. Matched as a whole token anywhere in the
# file, so inventory host names that are IPs, quoted or flow-style values count
# too; a vault-encrypted file cannot be checked and is refused as well.
lab_guard() {
  local v ip bad=0
  [ -f "$PROD_HOSTS" ] || return 0
  if head -c 14 "$PROD_HOSTS" | grep -qF '$ANSIBLE_VAULT'; then
    echo "run.sh: $PROD_HOSTS is vault-encrypted, cannot check the lab IPs against it: refusing" >&2
    exit 1
  fi
  for v in ENTRY_IP EXIT_IP EXIT2_IP CLIENT_IP ENTRY2_IP LAB_CLIENT_IP; do
    ip="${!v:-}"
    [ -n "$ip" ] || continue
    if grep -qwF -- "$ip" "$PROD_HOSTS"; then
      echo "run.sh: $v=$ip is a host in $PROD_HOSTS: refusing to touch a production host" >&2
      bad=1
    fi
  done
  [ "$bad" = 0 ] || exit 1
}
case "${1:-}" in
  init|swap-entry|deploy|client|check|swap|clean|guard) lab_guard ;;
esac

# Internet SSH bots keep the hosts' sshd at MaxStartups, which drops new
# connections at random: retry when the connection fails (255).
on() { # on <ip> <command...>
  local h="$1" rc try; shift
  for try in $(seq 1 "${ON_TRIES:-5}"); do
    ssh -i "$SSH_KEY" -o IdentitiesOnly=yes -o UserKnownHostsFile="$KNOWN_HOSTS" \
      -o StrictHostKeyChecking=yes -o BatchMode=yes -o ConnectTimeout=10 \
      "root@$h" "$@"
    rc=$?
    [ "$rc" = 255 ] || return "$rc"
    [ "$try" = "${ON_TRIES:-5}" ] || sleep $((try * 3))
  done
  return "$rc"
}

ap() { # ap <log-name> <ansible-playbook args...>; output in $LOGS/<log-name>.log
  local name="$1"; shift
  log "ansible-playbook $* (log: $LOGS/$name.log)"
  ANSIBLE_FORCE_COLOR=0 ANSIBLE_NOCOLOR=1 ANSIBLE_SSH_RETRIES=5 \
    uv run ansible-playbook -i "$INV" "$@" > "$LOGS/$name.log" 2>&1 < /dev/null
}

recap() { # recap <log-name> <host> <field>: value from PLAY RECAP
  awk -v h="$2" -v f="$3" '$1 == h && $2 == ":" { for (i = 3; i <= NF; i++) { split($i, a, "="); if (a[1] == f) print a[2] } }' \
    "$LOGS/$1.log" | tail -n 1
}

changed_tasks() { # changed_tasks <log-name>: "TASK [...]" names that reported changed
  awk '/^(TASK|RUNNING HANDLER) \[/ { t = $0 } /^changed: / { print t " -> " $2 }' "$LOGS/$1.log" | sort -u
}

labvar() { awk -v k="$1:" '$1 == k { print $2 }' "$INV/group_vars/all/lab.yml"; }

result() { # result PASS|FAIL <name> <evidence>
  local line
  line="$(printf '%-4s %-22s %s' "$1" "$2" "$3")"
  echo "$line"
  echo "$(date -u +%FT%TZ) $line" >> "$RESULTS"
}

# ----------------------------------------------------------------------------
# init

write_hosts() { # write_hosts <exit host name> <old exit host name or "">
  local exit_host="$1" old="$2" client_host exit2=""
  client_host=exit1
  [ -n "${EXIT2_IP:-}" ] && exit2="    exit2: {ansible_host: $EXIT2_IP}"
  [ -n "${EXIT2_IP:-}" ] && [ "$CLIENT_IP" = "$EXIT2_IP" ] && client_host=exit2
  if [ "$CLIENT_IP" != "${EXIT_IP}" ] && [ "$CLIENT_IP" != "${EXIT2_IP:-}" ]; then
    client_host=client1
    exit2="$exit2"$'\n'"    client1: {ansible_host: $CLIENT_IP}"
  fi
  cat > "$INV/hosts.yml" <<EOF
---
# Generated by tests/integration/run.sh. Do not commit.
all:
  vars:
    ansible_user: root
    ansible_ssh_private_key_file: $SSH_KEY
    ansible_ssh_common_args: -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN_HOSTS -o StrictHostKeyChecking=yes
  hosts:
    entry1: {ansible_host: $ENTRY_IP}
    exit1: {ansible_host: $EXIT_IP}
$exit2
  children:
    entry: {hosts: {entry1: {}}}
    entry_old: {}
    exit: {hosts: {$exit_host: {}}}
    exit_old: $([ -n "$old" ] && echo "{hosts: {$old: {}}}" || echo "{}")
    lab_client: {hosts: {$client_host: {}}}
EOF
}

cmd_init() {
  need ENTRY_IP EXIT_IP
  command -v age-keygen >/dev/null || die "age-keygen missing"
  local gv="$INV/group_vars/all"
  mkdir -p "$gv"
  cp "$ROOT/tests/integration/lab-vars.yml" "$gv/vars.yml"
  [ -s "$STATE/vault-pass" ] || (umask 077; openssl rand -hex 24 > "$STATE/vault-pass")
  [ -s "$STATE/age.key" ] || (umask 077; age-keygen -o "$STATE/age.key" 2>/dev/null)
  # Server identities: generated once, kept across re-runs.
  if [ ! -s "$gv/vault.yml" ]; then
    (umask 077
     uv run python - "$gv" "$STATE/age.key" <<'PY'
import pathlib, re, subprocess, sys
sys.path.insert(0, "plugins/filter")
import awg, yaml
gv, age_key = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
raw = subprocess.run([sys.executable, "scripts/gen-secrets.py", "all"], check=True,
                     capture_output=True, text=True).stdout
ports = re.search(r"entry_awg_port: (\d+), exit_awg_port: (\d+)", raw)
doc = yaml.safe_load(raw)
del doc["vault_backup_writer"], doc["vault_backup_reader"]  # -> vault_s3.yml
ident = [l for l in age_key.read_text().splitlines() if l.startswith("AGE-SECRET-KEY-")][0]
doc["vault_backup_age_identity"] = ident
doc["lab_client_key"] = {"private_key": awg.genkey()}
(gv / "vault.yml").write_text(yaml.safe_dump(doc, sort_keys=False, width=1000))
(gv / "vault_uplink.yml").write_text(subprocess.run(
    [sys.executable, "scripts/gen-secrets.py", "uplink-key"], check=True,
    capture_output=True, text=True).stdout)
(age_key.parent / "lab-ports").write_text(f"{ports[1]} {ports[2]}\n")
PY
    ) || die "generating secrets failed"
  fi
  # Also catches a half-finished earlier init that left them in plaintext.
  local f
  for f in "$gv/vault.yml" "$gv/vault_uplink.yml"; do
    [ "$(head -c 14 "$f")" = '$ANSIBLE_VAULT' ] && continue
    uv run ansible-vault encrypt "$f" >/dev/null || die "encrypting $f failed"
  done
  # S3 location and keys: rewritten on every init from .state/s3.env (never printed).
  (umask 077
   uv run python - "$gv" "$STATE/age.key" "$STATE/s3.env" <<'PY'
import pathlib, shlex, subprocess, sys
import yaml
gv, age_key, s3env = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
env = {}
if s3env.exists():
    for line in s3env.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip().removeprefix("export ").strip()] = (shlex.split(v) or [""])[0]
keys = ["BACKUP_S3_ENDPOINT", "BACKUP_S3_REGION", "BACKUP_S3_BUCKET", "BACKUP_S3_PREFIX",
        "WRITER_ACCESS_KEY", "WRITER_SECRET_KEY", "READER_ACCESS_KEY", "READER_SECRET_KEY"]
missing = [k for k in keys if not env.get(k)]
if s3env.exists() and missing:
    sys.exit(f"{s3env} lacks: {' '.join(missing)}")
configured = not missing
g = (lambda k, d: env[k]) if configured else (lambda k, d: d)
entry_port, exit_port = (age_key.parent / "lab-ports").read_text().split()
recipient = subprocess.run(["age-keygen", "-y", str(age_key)], check=True,
                           capture_output=True, text=True).stdout.strip()
(gv / "lab.yml").write_text(
    "---\n# Generated by tests/integration/run.sh init. Do not commit.\n" + yaml.safe_dump({
        "entry_awg_port": int(entry_port), "exit_awg_port": int(exit_port),
        "backup_s3_endpoint": g("BACKUP_S3_ENDPOINT", "https://s3.invalid"),
        "backup_s3_region": g("BACKUP_S3_REGION", "us-east-1"),
        "backup_s3_bucket": g("BACKUP_S3_BUCKET", "unset"),
        "backup_s3_prefix": g("BACKUP_S3_PREFIX", "multihop-lab"),
        "backup_age_recipient": recipient,
        "lab_s3_configured": configured,
        "lab_client_ip": "10.8.1.2",
    }, sort_keys=False))
(gv / "vault_s3.yml").write_text(yaml.safe_dump({
    "vault_backup_writer": {"access_key": g("WRITER_ACCESS_KEY", "unset"),
                            "secret_key": g("WRITER_SECRET_KEY", "unset")},
    "vault_backup_reader": {"access_key": g("READER_ACCESS_KEY", "unset"),
                            "secret_key": g("READER_SECRET_KEY", "unset")},
}, sort_keys=False))
print("S3: " + ("configured from " + str(s3env) if configured else "not configured (placeholders)"))
PY
  ) || die "writing the S3 settings failed"
  uv run ansible-vault encrypt "$gv/vault_s3.yml" >/dev/null || die "encrypting vault_s3.yml failed"
  # After `swap`, EXIT2 stays the exit.
  if [ -f "$STATE/swapped" ]; then write_hosts exit2 exit1; else write_hosts exit1 ""; fi
  uv run ansible-inventory -i "$INV" --graph
}

# ----------------------------------------------------------------------------
# deploy

cmd_deploy() {
  need ENTRY_IP EXIT_IP
  ap lab-pre tests/integration/lab.yml --tags pin,tools || die "lab.yml (pin,tools) failed, see $LOGS/lab-pre.log"
  ap site playbooks/site.yml || die "site.yml failed, see $LOGS/site.log"
  log "site.yml OK (includes verify.yml)"
  cmd_client
}

cmd_client() {
  ap lab-client tests/integration/lab.yml --tags client || die "lab.yml (client) failed, see $LOGS/lab-client.log"
  wait_client || die "the test client gets no traffic through the entry"
}

# ----------------------------------------------------------------------------
# helpers for checks

P() { labvar entry_awg_port; }

invvar() { # invvar <name> [default]: a var of the lab inventory's vars.yml (lab-vars.yml copy)
  local v
  v=$(awk -v k="$1:" '$1 == k { print $2 }' "$INV/group_vars/all/vars.yml")
  echo "${v:-${2:-}}"
}
transport() { invvar uplink_transport awg; }
reality() { [ "$(transport)" = reality ]; }
RPORT() { invvar exit_reality_port 443; }
TPORT() { invvar uplink_tproxy_port 12345; }

xcurl() { # the stock Xray client's SOCKS proxy (lab-xray-client on CLIENT_IP)
  on "$CLIENT_IP" curl -4 -s --max-time 15 --socks5-hostname 127.0.0.1:1080 "$@"
}

xray_client_up() { # until the stock Xray client reaches the internet via the entry's Xray (deploys it if needed)
  local _
  xcurl -o /dev/null https://1.1.1.1 && return 0
  ap lab-xray tests/integration/lab.yml --tags xray || return 1
  for _ in $(seq 1 20); do
    xcurl -o /dev/null https://1.1.1.1 && return 0
    sleep 3
  done
  return 1
}

uplink_conn() { # established TCP connections of the entry to the exit's REALITY port (<exit ip>)
  on "$ENTRY_IP" "ss -tnH state established dst $1:$(RPORT) | wc -l"
}

client() { on "$CLIENT_IP" "docker exec lab-client $(printf '%q ' "$@")"; }

client_curl() { client curl -4 -s --max-time 15 "$@"; }

wait_client() { # until the client reaches the internet through the entry
  for _ in $(seq 1 20); do
    client_curl -o /dev/null https://1.1.1.1 && return 0
    sleep 3
  done
  return 1
}

wait_uplink() { # [awg|reality]: until the uplink is up (awg: handshake younger than 180 s; reality: Xray container running)
  local age mode="${1:-$(transport)}"
  if [ "$mode" = reality ]; then
    for _ in $(seq 1 30); do
      [ "$(on "$ENTRY_IP" 'docker inspect -f "{{.State.Running}}" multihop-uplink-xray' 2>/dev/null)" = true ] && return 0
      sleep 2
    done
    return 1
  fi
  for _ in $(seq 1 30); do
    age=$(on "$ENTRY_IP" 'echo $(( $(date +%s) - $(docker exec multihop-uplink awg show awg-uplink latest-handshakes | awk "{print \$2}") ))' 2>/dev/null)
    [ -n "$age" ] && [ "$age" -lt 180 ] && return 0
    on "$ENTRY_IP" 'echo kick > /dev/udp/10.9.0.1/9' 2>/dev/null || true
    sleep 5
  done
  return 1
}

exit_bytes() { # total awg-exit transfer on the current exit (reality: bytes sent on its public interface)
  if reality; then
    on "$1" '. /etc/multihop/multihop.env && cat /sys/class/net/$PUBLIC_IFACE/statistics/tx_bytes'
    return
  fi
  on "$1" "docker exec multihop-exit awg show awg-exit transfer | awk '{ s += \$2 + \$3 } END { print s + 0 }'"
}

fwd_counter() { # fwd_counter direct|awg|drop: packets in MULTIHOP-FWD rules of that kind
  local pat
  case "$1" in
    direct) pat='mark match 0x5a/0xff' ;;
    awg) pat="udp spt:$(P)" ;;
    drop) pat='DROP' ;;
  esac
  on "$ENTRY_IP" "iptables -nvxL MULTIHOP-FWD" | awk -v p="$pat" 'index($0, p) { s += $1 } END { print s + 0 }'
}

pubif() { # pubif <ip>: the host's PUBLIC_IFACE from its multihop.env
  on "$1" '. /etc/multihop/multihop.env && echo "$PUBLIC_IFACE"'
}

capture() { # capture <ip> <seconds> <iface> <filter> > file (run in background)
  # tcpdump's stderr ("listening on ...") and its exit status are kept: a
  # capture that never ran must not read as "0 packets".
  on "$1" "timeout $2 tcpdump -lnni $3 '$4' 2>&1; echo tcpdump-rc=\$?"
}

pkts() { # pkts <capture file>: "<count>[ first: <packet>]", or "ERR(...)" if tcpdump did not run
  local n
  if ! grep -q '^listening on ' "$1" || ! grep -qx 'tcpdump-rc=124' "$1"; then
    echo "ERR($(grep -v '^[0-9][0-9]:' "$1" | tr '\n' ' ' | cut -c1-100))"; return
  fi
  n=$(grep -cE '^[0-9]{2}:[0-9]{2}:[0-9]{2}\.' "$1")
  if [ "$n" -gt 0 ]; then echo "$n first: $(grep -m1 -E '^[0-9]{2}:' "$1" | cut -c1-120)"; else echo 0; fi
}

ge1() { [ "${1%% *}" -ge 1 ] 2>/dev/null; } # count from pkts() >= 1 (ERR -> false)

listening() { # listening <capture file>...: wait (max 30 s) until every tcpdump listens
  local f _
  for _ in $(seq 1 60); do
    sleep 0.5
    for f in "$@"; do grep -q '^listening on ' "$f" 2>/dev/null || continue 2; done
    return 0
  done
  return 1
}

entry_hashes() {
  on "$ENTRY_IP" 'cd /var/lib/multihop/entry-awg && sha256sum awg0.conf clientsTable' | awk '{print $1}' | paste -sd' ' -
}

client_pub() {
  uv run ansible -i "$INV" entry1 -m debug \
    -a 'msg={{ lab_client_key.private_key | awg_pubkey }}' 2>/dev/null | awk -F'"' '/"msg"/ { print $4 }'
}

wait_ssh_cycle() { # wait until <ip> went away (if expected) and is back
  for _ in $(seq 1 30); do ON_TRIES=1 on "$1" true 2>/dev/null || break; sleep 2; done
  for _ in $(seq 1 60); do on "$1" 'systemctl is-system-running --wait >/dev/null 2>&1; true' 2>/dev/null && return 0; sleep 5; done
  return 1
}

# ----------------------------------------------------------------------------
# checks (stateful; the default order is the order below)

ck_first_run_reload() { # [log name]: handlers with state: reloaded on a unit not yet started
  # The exit swap's log is the first exit.yml on a fresh host (EXIT2).
  local f="$LOGS/${1:-swap}.log" ev
  [ -f "$f" ] || { result SKIP first_run_reload "no $f (run the exit swap: its exit.yml is a first run)"; return; }
  ev=$(awk '/^RUNNING HANDLER \[.*Reload multihop-(input-fw|net)\]/ { h = $0; getline; while ($0 ~ /^$/) getline; print h " => " $1 }' "$f" | sed 's/ \*\**//')
  if [ -n "$ev" ] && ! grep -q 'fatal' <<<"$ev"; then
    result PASS first_run_reload "$(tr '\n' ';' <<<"$ev")"
  else
    result FAIL first_run_reload "${ev:-no reload handler ran}"
  fi
}

ck_images_clean() {
  local imgs ps opt ref digest_ref
  imgs=$(on "$ENTRY_IP" "docker images --format '{{.Repository}}:{{.Tag}}' | grep amnezia | sort" | paste -sd' ' -)
  ps=$(on "$ENTRY_IP" "docker ps -a --format '{{.Names}} {{.Image}}' | grep amnezia | sort" | paste -sd' ' -)
  opt=$(on "$ENTRY_IP" 'ls -d /opt/amnezia 2>/dev/null')
  # The containerd image store hides digest-only references from `docker images`.
  ref="amneziavpn/amneziawg-go@$(awk '$1 == "awg_base_image_digest:" { print $2 }' "$INV/group_vars/all/vars.yml")"
  digest_ref=$(on "$ENTRY_IP" "docker image inspect -f '{{.Id}}' $ref 2>/dev/null")
  local want_imgs="amnezia-awg2:latest" want_ps="amnezia-awg2 amnezia-awg2"
  if [ "$(invvar entry_xray_enabled false)" = true ]; then # the app's Xray, built like the AWG one
    want_imgs="amnezia-awg2:latest amnezia-xray:latest"
    want_ps="amnezia-awg2 amnezia-awg2 amnezia-xray amnezia-xray"
  fi
  if [ "$imgs" = "$want_imgs" ] && [ "$ps" = "$want_ps" ] && [ -z "$opt" ] \
     && [ -z "$digest_ref" ]; then
    result PASS images_clean "images: $imgs; containers: $ps; host /opt/amnezia absent; no $ref reference"
  else
    result FAIL images_clean "images: '$imgs'; containers: '$ps'; /opt/amnezia: '$opt'; $ref: '$digest_ref'"
  fi
}

ck_to_ports() {
  local n
  n=$(on "$ENTRY_IP" "docker exec amnezia-awg2 iptables -t nat -S POSTROUTING | grep -c -- '-p udp .*--to-ports'")
  if [ "$n" = 2 ]; then result PASS to_ports "2 udp --to-ports MASQUERADE rules in amnezia-awg2"
  else result FAIL to_ports "count=$n"; fi
}

ck_idempotent() { # brief 3.1 (+ Review Focus 1 hashes recorded for peer_kept)
  local c tasks
  BEFORE_HASHES=$(entry_hashes)
  if ! ap idempotent playbooks/entry.yml; then
    result FAIL idempotent "entry.yml failed, see $LOGS/idempotent.log"; return
  fi
  c=$(recap idempotent entry1 changed)
  tasks=$(changed_tasks idempotent | grep -v "$ALWAYS_CHANGED" | paste -sd';' -)
  if [ "$c" = 0 ]; then result PASS idempotent "entry.yml re-run: changed=0"
  elif [ "$c" = 1 ] && [ -z "$tasks" ]; then
    result PASS idempotent "entry.yml re-run: changed=1, only '$ALWAYS_CHANGED' (refreshes the split sets every run by design)"
  else result FAIL idempotent "changed=$c: $tasks"; fi
}

ck_peer_kept() { # brief 3.2 / Review Focus 1
  local pub after live table
  pub=$(client_pub)
  [ -n "${BEFORE_HASHES:-}" ] || { BEFORE_HASHES=$(entry_hashes); ap peer-kept playbooks/entry.yml >/dev/null; }
  after=$(entry_hashes)
  live=$(on "$ENTRY_IP" "docker exec amnezia-awg2 awg show awg0 allowed-ips" | grep -F "$pub")
  table=$(on "$ENTRY_IP" "jq -r '.[].clientId' /var/lib/multihop/entry-awg/clientsTable" | grep -cF "$pub")
  if [ -n "$pub" ] && [ "$BEFORE_HASHES" = "$after" ] && [ -n "$live" ] && [ "$table" = 1 ] \
     && on "$ENTRY_IP" "grep -qF '$pub' /var/lib/multihop/entry-awg/awg0.conf"; then
    result PASS peer_kept "awg0.conf+clientsTable sha256 unchanged across entry.yml; live peer: $live"
  else
    result FAIL peer_kept "before='$BEFORE_HASHES' after='$after' live='$live' table=$table"
  fi
}

ck_client_via_exit() {
  local b a ip
  b=$(exit_bytes "$EXIT_NOW")
  ip=$(client_curl https://api.ipify.org)
  a=$(exit_bytes "$EXIT_NOW")
  local note=""
  [ "$CLIENT_IP" = "$EXIT_NOW" ] && note=" (client host IS the exit: the IP match alone does not discriminate)"
  if [ "$ip" = "$EXIT_NOW" ] && [ "$a" -gt "$b" ]; then
    result PASS client_via_exit "client egress IP $ip (= exit, client host $CLIENT_IP)$note; awg-exit bytes $b -> $a"
  else
    result FAIL client_via_exit "client egress '$ip' (exit $EXIT_NOW); awg-exit bytes $b -> $a"
  fi
}

ck_client_direct() {
  local b a ip
  b=$(fwd_counter direct)
  ip=$(client_curl https://ifconfig.me)
  a=$(fwd_counter direct)
  if [ "$ip" = "$ENTRY_IP" ] && [ "$a" -gt "$b" ]; then
    result PASS client_direct "client -> ifconfig.me shows entry IP $ip; direct RETURN pkts $b -> $a"
  else
    result FAIL client_direct "client -> ifconfig.me '$ip' (entry $ENTRY_IP); direct RETURN pkts $b -> $a"
  fi
}

ck_client_udp_sport() { # user UDP from source port entry_awg_port goes via the uplink
  local p q ent ext ans ct eif xif
  p=$(P); eif=$(pubif "$ENTRY_IP"); xif=$(pubif "$EXIT_NOW")
  q='\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01'
  capture "$ENTRY_IP" 15 "$eif" 'udp and host 1.1.1.1 and port 53' > "$STATE/cap-entry" &
  capture "$EXIT_NOW" 15 "$xif" 'udp and dst host 1.1.1.1 and dst port 53' > "$STATE/cap-exit" &
  listening "$STATE/cap-entry" "$STATE/cap-exit"
  ans=$(client bash -c "printf '$q' | timeout 5 nc -u -p $p -w 3 1.1.1.1 53 | wc -c" | tr -d ' ')
  ct=$(on "$ENTRY_IP" "conntrack -L -p udp --dst 1.1.1.1 --dport 53 2>/dev/null | grep -o 'sport=[0-9]*' | head -n 1")
  wait
  ent=$(pkts "$STATE/cap-entry"); ext=$(pkts "$STATE/cap-exit")
  if [ "$ent" = 0 ] && ge1 "$ext" && [ "${ans:-0}" -gt 0 ] 2>/dev/null; then
    result PASS client_udp_sport "client UDP sport $p -> 1.1.1.1:53: answer ${ans}B; entry $eif pkts=0, exit $xif pkts=$ext; host conntrack $ct"
  else
    result FAIL client_udp_sport "answer=${ans:-0}B entry $eif pkts=$ent exit $xif pkts=$ext conntrack $ct"
  fi
}

ck_client_fail_closed() {
  # Positive evidence that the client tried and the entry dropped it: its AWG
  # packets arrive on the public interface, the kernel's reverse-path counter
  # rises (with the uplink down, the reverse route for a client behind
  # amnezia-awg2 resolves via table 51820's blackhole, so loose rp_filter
  # drops the inbound packets), and nothing to 1.1.1.1 leaves. Packets seen
  # on the bridges and the MULTIHOP-FWD DROP delta are informational.
  local ent in rc eif p d0 d1 r0 r1 b n caps=() brs br=""
  # awg-uplink specific (stops multihop-uplink, reads the rp_filter counter); the
  # reality mode has fail_closed_reality_*.
  reality && { result SKIP client_fail_closed "uplink_transport=reality: see fail_closed_reality_*"; return; }
  eif=$(pubif "$ENTRY_IP"); p=$(P)
  brs=$(on "$ENTRY_IP" '. /etc/multihop/multihop.env && echo "$BRIDGES"')
  on "$ENTRY_IP" docker stop multihop-uplink >/dev/null
  d0=$(fwd_counter drop); r0=$(rpf_drops)
  capture "$ENTRY_IP" 20 "$eif" 'host 1.1.1.1' > "$STATE/cap-entry" &
  capture "$ENTRY_IP" 20 "$eif" "udp and src host $CLIENT_IP and dst port $p" > "$STATE/cap-in" &
  for b in $brs; do
    capture "$ENTRY_IP" 20 "$b" 'dst host 1.1.1.1' > "$STATE/cap-br-$b" &
    caps+=("$STATE/cap-br-$b")
  done
  listening "$STATE/cap-entry" "$STATE/cap-in" "${caps[@]}"
  client_curl -o /dev/null --max-time 8 https://1.1.1.1; rc=$?
  wait
  d1=$(fwd_counter drop); r1=$(rpf_drops)
  ent=$(pkts "$STATE/cap-entry"); in=$(pkts "$STATE/cap-in")
  for b in $brs; do n=$(pkts "$STATE/cap-br-$b"); br="$br $b=${n%% first:*}"; done
  on "$ENTRY_IP" docker start multihop-uplink >/dev/null
  wait_uplink && wait_client
  if [ "$rc" -ne 0 ] && [ "$ent" = 0 ] && ge1 "$in" && [ "$r1" -gt "$r0" ] 2>/dev/null; then
    result PASS client_fail_closed "uplink stopped: client curl rc=$rc; client AWG pkts in on $eif=${in%% first:*}; rp_filter drops $r0 -> $r1; pkts to/from 1.1.1.1 on $eif=0; bridges:$br; FWD DROP $d0 -> $d1; restored after start"
  else
    result FAIL client_fail_closed "uplink stopped: client curl rc=$rc; in=$in; rp_filter $r0 -> $r1; 1.1.1.1 on $eif=$ent; bridges:$br; FWD DROP $d0 -> $d1"
  fi
}

rpf_drops() { on "$ENTRY_IP" "nstat -asz TcpExtIPReversePathFilter | awk '/IPReversePathFilter/ { print \$2 }'"; }

ck_client_private_net() {
  # A provider private network on another NIC: user traffic to it must be
  # dropped on the entry (allow-list backstop), not leave unencrypted.
  local cap rc d0 d1
  on "$ENTRY_IP" 'ip link add mhpriv0 type dummy 2>/dev/null; ip addr replace 10.77.0.1/24 dev mhpriv0 && ip link set mhpriv0 up'
  d0=$(fwd_counter drop)
  capture "$ENTRY_IP" 15 mhpriv0 'host 10.77.0.5' > "$STATE/cap-priv" &
  listening "$STATE/cap-priv"
  client_curl -o /dev/null --max-time 6 http://10.77.0.5/; rc=$?
  wait
  d1=$(fwd_counter drop)
  cap=$(pkts "$STATE/cap-priv")
  on "$ENTRY_IP" 'ip link del mhpriv0'
  if [ "$rc" -ne 0 ] && [ "$cap" = 0 ] && [ "$d1" -gt "$d0" ]; then
    result PASS client_private_net "client -> 10.77.0.5 (dummy private NIC on the entry): curl rc=$rc, mhpriv0 pkts=0, MULTIHOP-FWD DROP $d0 -> $d1"
  else
    result FAIL client_private_net "curl rc=$rc, mhpriv0 pkts=$cap, MULTIHOP-FWD DROP $d0 -> $d1"
  fi
}

ck_idle_reply() { # server-initiated packet after the host conntrack entry expired
  local p ct eth up eif
  reality && { result SKIP idle_reply "uplink_transport=reality: no awg-uplink interface to compare against"; return; }
  p=$(P); eif=$(pubif "$ENTRY_IP")
  log "idle_reply: keeping the client silent for 135 s"
  sleep 135
  ct=$(on "$ENTRY_IP" "conntrack -L -p udp --orig-port-dst $p 2>/dev/null | grep -c 'src=$CLIENT_IP'")
  capture "$ENTRY_IP" 15 "$eif" "udp and src port $p and dst host $CLIENT_IP" > "$STATE/cap-entry" &
  capture "$ENTRY_IP" 15 awg-uplink "host $CLIENT_IP" > "$STATE/cap-uplink" &
  listening "$STATE/cap-entry" "$STATE/cap-uplink"
  on "$ENTRY_IP" "docker exec amnezia-awg2 ping -c 3 -W 1 $CLIENT_TUN_IP" >/dev/null 2>&1
  wait
  eth=$(pkts "$STATE/cap-entry"); up=$(pkts "$STATE/cap-uplink")
  wait_client || wait_client
  if [ "$ct" = 0 ] && ge1 "$eth" && [ "$up" = 0 ]; then
    result PASS idle_reply "after 135 s idle (conntrack entries for client: 0) ping from amnezia-awg2: $eif udp sport $p -> client pkts=$eth, awg-uplink pkts=0; client reconnects"
  else
    result FAIL idle_reply "conntrack entries=$ct $eif sport $p pkts=$eth awg-uplink pkts=$up"
  fi
}

ck_group_heal() { # public interface group: verify catches its loss, reresolve restores it, udev matches
  local eif vf healed=0 udev t
  eif=$(pubif "$ENTRY_IP")
  on "$ENTRY_IP" "ip link set dev $eif group default"
  ap verify-nogroup playbooks/verify.yml
  vf=$(grep -c 'not in group 51820' "$LOGS/verify-nogroup.log")
  for t in $(seq 1 18); do  # the re-resolve timer runs every minute
    if on "$ENTRY_IP" "ip -d link show dev $eif | grep -qw 'group 51820'"; then healed=$((t * 5)); break; fi
    sleep 5
  done
  udev=$(on "$ENTRY_IP" "udevadm test /sys/class/net/$eif 2>&1 | grep -c 'ip link set dev .* group 51820'")
  [ "$healed" -gt 0 ] || on "$ENTRY_IP" "ip link set dev $eif group 51820"
  if [ "$vf" -ge 1 ] && [ "$healed" -gt 0 ] && [ "${udev:-0}" -ge 1 ]; then
    result PASS group_heal "group removed from $eif: verify.yml failed on it; multihop-reresolve restored it within ${healed}s; udevadm test runs the group rule"
  else
    result FAIL group_heal "verify failed on group: $vf; healed after: ${healed}s; udev rule matched: ${udev:-0}"
  fi
}

ck_verify_fail_closed() { # brief 3.3
  if ap verify-fc playbooks/verify.yml -e verify_fail_closed=true; then
    result PASS verify_fail_closed "verify.yml -e verify_fail_closed=true ok ($(recap verify-fc entry1 ok) ok)"
  else result FAIL verify_fail_closed "see $LOGS/verify-fc.log"; fi
  wait_client
}

RULES_EXPECTED="rules=6 drops=2 group=1"
rules_ok() { # "rules=<ip rules 10100-10130> drops=<MULTIHOP-FWD DROPs> group=<public iface in 51820>"
  on "$ENTRY_IP" '. /etc/multihop/multihop.env
    echo "rules=$(ip rule | grep -cE "^101[0-3]0:") drops=$(iptables -S MULTIHOP-FWD | grep -c -- "-j DROP")" \
      "group=$(ip -d link show dev "$PUBLIC_IFACE" | grep -cw "group 51820")"'
}

ck_docker_restart() { # brief 3.4
  local r
  on "$ENTRY_IP" systemctl restart docker
  r=$(rules_ok)
  if [ "$r" = "$RULES_EXPECTED" ] && ap verify-docker playbooks/verify.yml && wait_client; then
    result PASS docker_restart "after systemctl restart docker: ip rules/FWD drops '$r'; verify.yml ok; client back"
  else
    result FAIL docker_restart "rules '$r'; see $LOGS/verify-docker.log"
  fi
}

ck_reboot() { # brief 3.5 / Review Focus 2
  local r order
  ON_TRIES=1 on "$ENTRY_IP" 'systemctl reboot' 2>/dev/null  # never twice
  wait_ssh_cycle "$ENTRY_IP" || { result FAIL reboot "entry did not come back"; return; }
  r=$(rules_ok)
  order=$(on "$ENTRY_IP" 'n=$(systemctl show -P ActiveEnterTimestampMonotonic multihop-net); d=$(systemctl show -P ExecMainStartTimestampMonotonic docker); echo "multihop-net=$n docker-start=$d"; [ "$n" -gt 0 ] && [ "$n" -lt "$d" ]')
  local ok=$?
  if [ "$ok" = 0 ] && [ "$r" = "$RULES_EXPECTED" ] \
     && ap verify-reboot playbooks/verify.yml -e verify_fail_closed=true && wait_client; then
    result PASS reboot "after reboot: $order (net before docker); rules '$r'; verify fail_closed ok; client back"
  else
    result FAIL reboot "order: $order (ok=$ok); rules '$r'; see $LOGS/verify-reboot.log"
  fi
}

ck_container_direct() { # brief 3.6
  local b a ip
  b=$(fwd_counter direct)
  ip=$(on "$ENTRY_IP" docker exec amnezia-awg2 curl -4 -s --max-time 15 ifconfig.me)
  a=$(fwd_counter direct)
  if [ "$a" -gt "$b" ] && [ "$ip" = "$ENTRY_IP" ]; then
    result PASS container_direct "amnezia-awg2 curl ifconfig.me = entry IP $ip; direct RETURN pkts $b -> $a"
  else
    result FAIL container_direct "ip '$ip'; direct RETURN pkts $b -> $a"
  fi
}

s3_creds() { # reader keys from the vault, as "access secret" (never printed)
  uv run ansible -i "$INV" entry1 -m debug \
    -a 'msg="{{ vault_backup_reader.access_key }} {{ vault_backup_reader.secret_key }}"' 2>/dev/null \
    | awk -F'"' '/"msg"/ { print $4 }'
}

s3_count() { # s3_count <access> <secret>: object versions under <prefix>/entry-
  AWS_ACCESS_KEY_ID="$1" AWS_SECRET_ACCESS_KEY="$2" AWS_DEFAULT_REGION="$(labvar backup_s3_region)" \
    aws --endpoint-url "$(labvar backup_s3_endpoint)" s3api list-object-versions \
    --bucket "$(labvar backup_s3_bucket)" --prefix "$(labvar backup_s3_prefix)/entry-" \
    --query 'length(Versions || `[]`)' --output text
}

s3_ready() { # backup checks need .state/s3.env (then `run.sh init` and entry.yml)
  [ "$(labvar lab_s3_configured)" = true ] && return 0
  result SKIP "$1" "no $STATE/s3.env yet"
  return 1
}

ck_backup() { # brief 3.7
  local creds n0 n1 n2 out
  s3_ready backup || return
  read -r -a creds <<<"$(s3_creds)"
  n0=$(s3_count "${creds[@]}")
  ap backup playbooks/backup.yml || { result FAIL backup "backup.yml failed, see $LOGS/backup.log"; return; }
  n1=$(s3_count "${creds[@]}")
  on "$ENTRY_IP" systemctl start multihop-backup
  out=$(on "$ENTRY_IP" 'journalctl -u multihop-backup -n 3 --no-pager -o cat' | grep -m1 'unchanged')
  n2=$(s3_count "${creds[@]}")
  if [ "$n1" -gt "$n0" ] && [ "$n2" = "$n1" ] && [ -n "$out" ]; then
    result PASS backup "backup.yml: object versions $n0 -> $n1; timer run: '$out', versions $n2"
  else
    result FAIL backup "versions $n0 -> $n1 -> $n2; unchanged msg '$out'"
  fi
}

image_label() { # label of the image amnezia-awg2 runs ('' if none)
  on "$ENTRY_IP" 'img=$(docker inspect -f "{{.Image}}" amnezia-awg2) && docker image inspect -f "{{index .Config.Labels \"org.multihop.build\"}}" "$img"' 2>/dev/null
}

ck_drift() { # brief 3.8 / Review Focus 5, as a real app reinstall
  # The app reinstall: remove the image, rebuild amnezia-awg2 from the
  # upstream Dockerfile (upstream base, its start.sh without our UDP port
  # exclusion; legacy builder, as the app gets on a host without buildx) and
  # run it without the bind mount. restore.yml must rebuild OUR image.
  local p st drift msg pub live before after
  s3_ready drift || return
  p=$(P)
  pub=$(client_pub)
  on "$ENTRY_IP" "set -e; d=/var/tmp/app-reinstall; rm -rf \$d; mkdir -p \$d
    sed 's#^FROM .*#FROM amneziavpn/amneziawg-go:latest#' /var/lib/multihop/entry-app-build/Dockerfile > \$d/Dockerfile
    grep -v -- '--to-ports' /var/lib/multihop/entry-app-build/start.sh > \$d/start.sh
    docker rm -f amnezia-awg2 >/dev/null; docker rmi amnezia-awg2 >/dev/null
    DOCKER_BUILDKIT=0 docker build -q --pull -t amnezia-awg2 \$d >/dev/null 2>&1
    docker run -d --name amnezia-awg2 --restart always --privileged --cap-add NET_ADMIN --cap-add SYS_MODULE \
      -p $p:$p/udp -v /lib/modules:/lib/modules amnezia-awg2 >/dev/null
    docker network connect amnezia-dns-net amnezia-awg2; rm -rf \$d"
  before=$(image_label)
  on "$ENTRY_IP" systemctl start multihop-backup 2>/dev/null
  st=$(on "$ENTRY_IP" systemctl show -P ExecMainStatus multihop-backup)
  drift=$(on "$ENTRY_IP" 'test -f /var/lib/multihop/backup/DRIFT && echo DRIFT')
  ap drift-entry playbooks/entry.yml
  msg=$(grep -o 'restore.yml[^"]*' "$LOGS/drift-entry.log" | head -n 1)
  if ! ap drift-restore playbooks/restore.yml -e confirm=yes; then
    result FAIL drift "backup exit=$st $drift; entry.yml msg '$msg'; restore.yml failed, see $LOGS/drift-restore.log"; return
  fi
  after=$(image_label)
  # The simulated app left the upstream tag behind; the real app would too.
  on "$ENTRY_IP" 'docker rmi amneziavpn/amneziawg-go:latest >/dev/null 2>&1; true'
  live=$(on "$ENTRY_IP" "docker exec amnezia-awg2 awg show awg0 allowed-ips" | grep -F "$pub")
  if [ "$st" = 2 ] && [ "$drift" = DRIFT ] && [ "$(recap drift-entry entry1 failed)" = 1 ] && [ -n "$msg" ] \
     && [ -z "$before" ] && [[ "$after" =~ ^[0-9a-f]{64}$ ]] \
     && [ -n "$live" ] && ap drift-verify playbooks/verify.yml && wait_client; then
    result PASS drift "app-reinstalled image (label '$before') without mount: backup exit=2 + DRIFT; entry.yml failed naming '$msg'; restore.yml rebuilt our image (label ${after:0:12}...), peer back ($live); verify ok (incl. to_ports=2, label); client back"
  else
    result FAIL drift "label before '$before' after '$after'; backup exit=$st '$drift'; entry.yml failed=$(recap drift-entry entry1 failed) msg='$msg'; peer='$live'"
  fi
}

ck_exit_docker_restart() { # exit forwarding survives `systemctl stop docker; systemctl start docker`
  local st
  st=$(on "$EXIT_NOW" 'systemctl stop docker docker.socket; systemctl start docker
    for _ in $(seq 1 30); do systemctl is-active -q multihop-net && break; sleep 1; done
    echo "multihop-net=$(systemctl is-active multihop-net) fwd=$(iptables -S MULTIHOP-FWD 2>/dev/null | grep -c -- -j) nat=$(iptables -t nat -S MULTIHOP-NAT 2>/dev/null | grep -c MASQUERADE)"')
  if [[ "$st" == "multihop-net=active fwd="* && "$st" != *"fwd=0"* && "$st" == *"nat=1" ]] && wait_uplink && wait_client \
     && [ "$(client_curl https://api.ipify.org)" = "$EXIT_NOW" ]; then
    result PASS exit_docker_restart "exit after docker stop+start: $st; client egress via exit again"
  else
    result FAIL exit_docker_restart "exit after docker stop+start: $st"
  fi
}

ck_client_metadata() { # the exit's provider metadata / private ranges are unreachable for users
  local rc xif cap d0 d1
  xif=$(pubif "$EXIT_NOW")
  d0=$(on "$EXIT_NOW" "iptables -nvxL MULTIHOP-FWD | awk '/169.254.0.0\/16/ { print \$1 }'")
  capture "$EXIT_NOW" 15 "$xif" 'host 169.254.169.254' > "$STATE/cap-md" &
  listening "$STATE/cap-md"
  client_curl -o /dev/null --max-time 6 http://169.254.169.254/; rc=$?
  wait
  d1=$(on "$EXIT_NOW" "iptables -nvxL MULTIHOP-FWD | awk '/169.254.0.0\/16/ { print \$1 }'")
  cap=$(pkts "$STATE/cap-md")
  if [ "$rc" -ne 0 ] && [ "$cap" = 0 ] && [ "${d1:-0}" -gt "${d0:-0}" ] 2>/dev/null; then
    result PASS client_metadata "client -> 169.254.169.254: curl rc=$rc; exit $xif pkts=0; exit 169.254/16 DROP $d0 -> $d1"
  else
    result FAIL client_metadata "curl rc=$rc; exit $xif pkts=$cap; DROP $d0 -> $d1"
  fi
}

ck_docker_blocked() { # Docker must not start on the entry when the entry rules cannot be applied
  local st
  st=$(on "$ENTRY_IP" 'chmod -x /usr/local/sbin/multihop-entry-net; systemctl restart docker 2>/dev/null; rc=$?
    echo "restart_rc=$rc docker=$(systemctl is-active docker) app=$(docker inspect -f {{.State.Running}} amnezia-awg2 2>/dev/null || echo none)"
    chmod +x /usr/local/sbin/multihop-entry-net
    systemctl reset-failed docker docker.socket; systemctl start docker')  # past the start rate limit
  # Docker keeps retrying its ExecStartPre ("activating") or gives up ("failed").
  if [[ "$st" =~ docker=(failed|inactive|activating) ]] && [[ "$st" != *"app=true"* ]] \
     && [[ "$st" != *"restart_rc=0"* ]] && wait_uplink && wait_client; then
    result PASS docker_blocked "multihop-entry-net not runnable: $st; after fixing it Docker and the client are back"
  else
    result FAIL docker_blocked "$st"
  fi
}

# ----------------------------------------------------------------------------
# Xray uplink (uplink_transport: reality) and the app's Xray on the entry

need_reality() { # need_reality <check>: SKIP unless the lab runs the Xray uplink
  reality && return 0
  result SKIP "$1" "uplink_transport=$(transport), not reality"
  return 1
}

ck_reality_uplink() {
  need_reality reality_uplink || return
  local ip lst conn
  ip=$(client_curl https://api.ipify.org)
  lst=$(on "$ENTRY_IP" "ss -ltnH 'sport = :$(TPORT)'" | awk '{print $4}' | paste -sd' ' -)
  conn=$(uplink_conn "$EXIT_NOW")
  if [ -n "$lst" ] && [ "${conn:-0}" -ge 1 ] 2>/dev/null && [ "$ip" = "$EXIT_NOW" ]; then
    result PASS reality_uplink "multihop-uplink-xray listens on $lst; $conn established TCP to $EXIT_NOW:$(RPORT); AWG client egress $ip (= exit)"
  else
    result FAIL reality_uplink "listen '$lst'; established to $EXIT_NOW:$(RPORT) = '$conn'; AWG client egress '$ip' (exit $EXIT_NOW)"
  fi
}

ck_reality_throughput() { # 20 s download from the AWG client through the whole path
  need_reality reality_throughput || return
  local bps mbit
  bps=$(client_curl --max-time 20 -o /dev/null -w '%{speed_download}' 'https://speed.cloudflare.com/__down?bytes=99000000')
  mbit=$(awk -v b="${bps:-0}" 'BEGIN { printf "%.1f", b * 8 / 1000000 }')
  if awk -v m="$mbit" 'BEGIN { exit !(m > 1) }'; then
    result PASS reality_throughput "AWG client -> entry -> Xray uplink -> exit -> speed.cloudflare.com: $mbit Mbit/s (20 s max)"
  else
    result FAIL reality_throughput "$mbit Mbit/s (speed_download '${bps:-}')"
  fi
}

# fail_closed_reality <check> <ip> <container>: stop <container> on <ip>; neither the
# AWG client nor the Xray client reaches the internet; start it again.
fail_closed_reality() {
  local name="$1" host="$2" ctr="$3" pre_awg pre_x rc_awg rc_x eif cap
  eif=$(pubif "$ENTRY_IP")
  # Pre-checks: both clients must work, or a failing curl while stopped proves nothing.
  if ! { wait_client && xray_client_up; }; then
    result FAIL "$name" "a client gets no traffic before the test"; return
  fi
  pre_awg=$(client_curl https://api.ipify.org)
  pre_x=$(xcurl https://api.ipify.org)
  if [ "$pre_awg" != "$EXIT_NOW" ] || [ "$pre_x" != "$EXIT_NOW" ]; then
    result FAIL "$name" "pre-check: AWG client egress '$pre_awg', Xray client egress '$pre_x' (exit $EXIT_NOW)"; return
  fi
  capture "$ENTRY_IP" 20 "$eif" 'host 1.1.1.1' > "$STATE/cap-entry" &
  listening "$STATE/cap-entry"
  # An interrupt must not leave the service stopped.
  trap 'on "$host" "docker start $ctr" >/dev/null 2>&1' EXIT
  trap 'exit 130' INT TERM
  on "$host" "docker stop $ctr >/dev/null"
  client_curl -o /dev/null --max-time 8 https://1.1.1.1; rc_awg=$?
  xcurl -o /dev/null --max-time 8 https://1.1.1.1; rc_x=$?
  wait
  cap=$(pkts "$STATE/cap-entry")
  on "$host" "docker start $ctr >/dev/null"
  trap - EXIT INT TERM
  wait_uplink && wait_client && xray_client_up
  if [ "$rc_awg" -ne 0 ] && [ "$rc_x" -ne 0 ] && [ "$cap" = 0 ]; then
    result PASS "$name" "$ctr stopped on $host: AWG client curl rc=$rc_awg, Xray client curl rc=$rc_x (both egressed via $EXIT_NOW before); pkts to/from 1.1.1.1 on entry $eif=0; restored after start"
  else
    result FAIL "$name" "$ctr stopped on $host: AWG client curl rc=$rc_awg, Xray client curl rc=$rc_x; entry $eif pkts to/from 1.1.1.1=$cap"
  fi
}

ck_fail_closed_reality_entry_xray() {
  need_reality fail_closed_reality_entry_xray || return
  fail_closed_reality fail_closed_reality_entry_xray "$ENTRY_IP" multihop-uplink-xray
}

ck_fail_closed_reality_exit_xray() {
  need_reality fail_closed_reality_exit_xray || return
  fail_closed_reality fail_closed_reality_exit_xray "$EXIT_NOW" multihop-exit-xray
}

ck_fail_closed_reality_no_tproxy() { # the chain flushed: marked packets go to `local`, nothing leaves
  need_reality fail_closed_reality_no_tproxy || return
  local rc eif cap n
  eif=$(pubif "$ENTRY_IP")
  wait_client || { result FAIL fail_closed_reality_no_tproxy "the AWG client gets no traffic before the test"; return; }
  capture "$ENTRY_IP" 15 "$eif" 'host 1.1.1.1' > "$STATE/cap-entry" &
  listening "$STATE/cap-entry"
  # An interrupt must not leave the chain flushed.
  trap 'on "$ENTRY_IP" "systemctl reload multihop-net" >/dev/null 2>&1' EXIT
  trap 'exit 130' INT TERM
  on "$ENTRY_IP" 'iptables -t mangle -F MULTIHOP-TPROXY'
  client_curl -o /dev/null --max-time 8 https://1.1.1.1; rc=$?
  wait
  cap=$(pkts "$STATE/cap-entry")
  on "$ENTRY_IP" 'systemctl reload multihop-net'
  trap - EXIT INT TERM
  n=$(on "$ENTRY_IP" 'iptables -t mangle -S MULTIHOP-TPROXY | grep -c -- "-j TPROXY"')
  wait_client
  if [ "$rc" -ne 0 ] && [ "$cap" = 0 ] && [ "${n:-0}" -ge 1 ]; then
    result PASS fail_closed_reality_no_tproxy "MULTIHOP-TPROXY flushed: AWG client curl rc=$rc, pkts to/from 1.1.1.1 on $eif=0; systemctl reload multihop-net restored $n TPROXY rule(s), client back"
  else
    result FAIL fail_closed_reality_no_tproxy "curl rc=$rc; $eif pkts=$cap; TPROXY rules after reload=$n"
  fi
}

ck_icmp_blocked_reality() {
  need_reality icmp_blocked_reality || return
  local out recv
  out=$(client ping -c 3 -W 2 1.1.1.1 2>&1)
  recv=$(grep -oE '[0-9]+ packets received' <<<"$out" | awk '{print $1}')
  if [ "$recv" = 0 ]; then
    result PASS icmp_blocked_reality "ping -c 3 1.1.1.1 from the AWG client: 0 packets received"
  else
    result FAIL icmp_blocked_reality "received='$recv': $(tr '\n' ' ' <<<"$out" | cut -c1-160)"
  fi
}

ck_direct_and_force_exit_reality() { # lab: 1.0.0.0/24 direct; 1.1.1.1/32 forced through the exit inside the direct 1.1.1.0/24
  need_reality direct_and_force_exit_reality || return
  local d b a dip fip
  b=$(fwd_counter direct)
  dip=$(client_curl https://1.0.0.1/cdn-cgi/trace | awk -F= '$1 == "ip" { print $2 }')
  a=$(fwd_counter direct)
  fip=$(client_curl https://1.1.1.1/cdn-cgi/trace | awk -F= '$1 == "ip" { print $2 }')
  d=$(on "$ENTRY_IP" 'ipset list multihop_force_exit 2>/dev/null | grep -c "^1.1.1.1"')
  if [ "$dip" = "$ENTRY_IP" ] && [ "$a" -gt "$b" ] && [ "$fip" = "$EXIT_NOW" ] && [ "${d:-0}" -ge 1 ]; then
    result PASS direct_and_force_exit_reality "direct 1.0.0.1 shows entry IP $dip (direct RETURN pkts $b -> $a); force-exit 1.1.1.1 inside direct 1.1.1.0/24 shows exit IP $fip"
  else
    result FAIL direct_and_force_exit_reality "direct 1.0.0.1 '$dip' (entry $ENTRY_IP, pkts $b -> $a); force-exit 1.1.1.1 '$fip' (exit $EXIT_NOW); force set entries=$d"
  fi
}

ck_xray_client_via_exit() {
  local ip dip ok=0 added
  # Adds the user like the app: server.json append + docker restart amnezia-xray.
  ap lab-xray tests/integration/lab.yml --tags xray || { result FAIL xray_client_via_exit "lab.yml (xray) failed, see $LOGS/lab-xray.log"; return; }
  added=$(grep -c 'changed: \[entry1\]' "$LOGS/lab-xray.log")
  for _ in $(seq 1 20); do
    xcurl -o /dev/null https://1.1.1.1 && { ok=1; break; }
    sleep 3
  done
  ip=$(xcurl https://api.ipify.org)
  dip=$(xcurl https://ifconfig.me)
  local note=""
  [ "$CLIENT_IP" = "$EXIT_NOW" ] && note=" (client host IS the exit: the IP match alone does not discriminate)"
  if [ "$ok" = 1 ] && [ "$ip" = "$EXIT_NOW" ] && [ "$dip" = "$ENTRY_IP" ]; then
    result PASS xray_client_via_exit "stock Xray client (VLESS+REALITY+vision, user added to server.json like the app; entry tasks changed=$added): egress $ip (= exit)$note; direct-list ifconfig.me shows entry IP $dip"
  else
    result FAIL xray_client_via_exit "client up=$ok; egress '$ip' (exit $EXIT_NOW); ifconfig.me '$dip' (entry $ENTRY_IP)"
  fi
}

ck_xray_restart_keeps_settings() { # Review Focus 5: the settings the app's run script does not give a restarted container
  [ "$(invvar entry_xray_enabled false)" = true ] || { result SKIP xray_restart_keeps_settings "entry_xray_enabled is not true"; return; }
  local mount range lo hi cc dl
  xray_client_up || { result FAIL xray_restart_keeps_settings "the Xray client gets no traffic before the restart"; return; }
  on "$ENTRY_IP" 'docker restart amnezia-xray >/dev/null'
  xray_client_up
  mount=$(on "$ENTRY_IP" "docker inspect -f '{{range .Mounts}}{{.Type}}:{{.Source}}:{{.Destination}} {{end}}' amnezia-xray")
  range=$(on "$ENTRY_IP" 'docker exec amnezia-xray cat /proc/sys/net/ipv4/ip_local_port_range')
  read -r lo hi <<<"$range"
  # An active connection: a download through the Xray client, inspected in the container's netns.
  xcurl --max-time 12 -o /dev/null 'https://speed.cloudflare.com/__down?bytes=99000000' &
  dl=$!
  sleep 5
  cc=$(on "$ENTRY_IP" 'pid=$(docker inspect -f "{{.State.Pid}}" amnezia-xray); nsenter -t "$pid" -n ss -tin state established | grep -c bbr')
  kill "$dl" 2>/dev/null; wait "$dl" 2>/dev/null
  if [[ "$mount" == *"bind:/var/lib/multihop/entry-xray:/opt/amnezia/xray"* ]] \
     && [ -n "$lo" ] && { [ "$(P)" -lt "$lo" ] || [ "$(P)" -gt "$hi" ]; } && [ "${cc:-0}" -ge 1 ] 2>/dev/null; then
    result PASS xray_restart_keeps_settings "after docker restart amnezia-xray: mounts '${mount% }'; ip_local_port_range '$lo $hi' excludes entry_awg_port $(P); $cc established connection(s) with bbr"
  else
    result FAIL xray_restart_keeps_settings "mounts '$mount'; ip_local_port_range '$range' (entry_awg_port $(P)); bbr connections=$cc"
  fi
}

ck_leak_awg_tcp_sport_443() { # a bridge client's TCP source port 443 must not match the Xray reply exception
  need_reality leak_awg_tcp_sport_443 || return
  local eif ip cap
  eif=$(pubif "$ENTRY_IP")
  # Only a SYN with source port 443 can be a leaked client flow (the entry's own
  # Xray answers from 443 but never opens a connection from it).
  capture "$ENTRY_IP" 15 "$eif" 'tcp[tcpflags] == tcp-syn and src port 443' > "$STATE/cap-entry" &
  listening "$STATE/cap-entry"
  ip=$(client_curl --local-port 443 https://api.ipify.org)
  wait
  cap=$(pkts "$STATE/cap-entry")
  if [ "$ip" = "$EXIT_NOW" ] && [ "$cap" = 0 ]; then
    result PASS leak_awg_tcp_sport_443 "AWG client curl --local-port 443: egress $ip (= exit); no outbound SYN with source port 443 on $eif"
  else
    result FAIL leak_awg_tcp_sport_443 "egress '$ip' (exit $EXIT_NOW); $eif SYN sport 443 pkts=$cap"
  fi
}

ck_rollback_to_awg() { # Review Focus 2: reality -> awg -> reality
  need_reality rollback_to_awg || return
  local ctr run ep chain lroutes ip ok=1 why=""
  if ! ap rollback-awg playbooks/entry.yml -e uplink_transport=awg; then
    result FAIL rollback_to_awg "entry.yml -e uplink_transport=awg failed, see $LOGS/rollback-awg.log"
    ap rollback-back playbooks/entry.yml; return
  fi
  wait_uplink awg && wait_client
  ctr=$(on "$ENTRY_IP" 'docker inspect -f "{{.Name}}" multihop-uplink-xray 2>&1' | grep -c 'No such')
  run=$(on "$ENTRY_IP" 'docker inspect -f "{{.State.Running}}" multihop-uplink')
  ep=$(on "$ENTRY_IP" 'docker exec multihop-uplink awg show awg-uplink endpoints' | awk '{print $2}')
  chain=$(on "$ENTRY_IP" 'iptables -t mangle -S MULTIHOP-TPROXY >/dev/null 2>&1; echo $?')
  lroutes=$(on "$ENTRY_IP" 'ip route show table 51820 | grep -c "^local"')
  ip=$(client_curl https://api.ipify.org)
  [ "$ctr" = 1 ] || why="$why multihop-uplink-xray still exists;"
  [ "$run" = true ] || why="$why multihop-uplink not running;"
  [ "$ep" = "$EXIT_NOW:$(labvar exit_awg_port)" ] || why="$why endpoint '$ep';"
  [ "$chain" != 0 ] || why="$why MULTIHOP-TPROXY present;"
  [ "$lroutes" = 0 ] || why="$why table 51820 has $lroutes local route(s);"
  [ "$ip" = "$EXIT_NOW" ] || why="$why AWG client egress '$ip';"
  [ -z "$why" ] || ok=0
  # Back to reality, as the inventory says.
  if ! ap rollback-back playbooks/entry.yml; then
    result FAIL rollback_to_awg "awg phase ok=$ok ($why); entry.yml back to reality failed, see $LOGS/rollback-back.log"; return
  fi
  wait_uplink reality && wait_client
  if [ "$ok" = 1 ]; then
    result PASS rollback_to_awg "-e uplink_transport=awg: multihop-uplink-xray gone, multihop-uplink running (endpoint $ep), MULTIHOP-TPROXY absent, no local route in table 51820, client egress $ip; then back to reality:"
  else
    result FAIL rollback_to_awg "awg phase:$why"
  fi
  ck_reality_uplink
}

ck_xray_app_user_backup_valid() { # a real app-style server.json edit must pass the strict backup validation
  [ "$(invvar entry_xray_enabled false)" = true ] || { result SKIP xray_app_user_backup_valid "entry_xray_enabled is not true"; return; }
  s3_ready xray_app_user_backup_valid || return
  local st out
  xray_client_up || { result FAIL xray_app_user_backup_valid "the Xray client is not up (user not added)"; return; }
  on "$ENTRY_IP" systemctl start multihop-backup
  st=$(on "$ENTRY_IP" systemctl show -P ExecMainStatus multihop-backup)
  # fetch-backup.yml validates with backup_archive_problems (xray/server.json strict shape).
  if ! ap backup-valid tests/integration/fetch-check.yml; then
    result FAIL xray_app_user_backup_valid "backup exit=$st; fetch/validate refused the backup, see $LOGS/backup-valid.log"; return
  fi
  out=$(grep -o 'backup-valid has_xray=[A-Za-z]* lab_client_in_backup=[A-Za-z]*' "$LOGS/backup-valid.log" | head -n 1)
  if [ "$st" = 0 ] && [ "$out" = 'backup-valid has_xray=True lab_client_in_backup=True' ]; then
    result PASS xray_app_user_backup_valid "app-edited server.json (client added, amnezia-xray restarted) backed up (exit=$st); backup_archive_problems accepted it; $out"
  else
    result FAIL xray_app_user_backup_valid "backup exit=$st; '$out'"
  fi
}

CHECKS="first_run_reload images_clean to_ports idempotent peer_kept client_via_exit client_direct
client_udp_sport client_fail_closed client_private_net idle_reply group_heal verify_fail_closed docker_restart reboot
container_direct client_metadata exit_docker_restart docker_blocked backup drift
reality_uplink reality_throughput direct_and_force_exit_reality icmp_blocked_reality leak_awg_tcp_sport_443
xray_client_via_exit xray_restart_keeps_settings xray_app_user_backup_valid
fail_closed_reality_entry_xray fail_closed_reality_exit_xray fail_closed_reality_no_tproxy rollback_to_awg"

cmd_check() {
  need ENTRY_IP EXIT_IP CLIENT_IP
  if [ -f "$STATE/swapped" ]; then EXIT_NOW="${EXIT_NOW:-$EXIT2_IP}"; else EXIT_NOW="${EXIT_NOW:-$EXIT_IP}"; fi
  local c
  # shellcheck disable=SC2086 # default list is word-split on purpose
  [ "$#" -gt 0 ] || set -- $CHECKS
  for c in "$@"; do
    log "check $c"
    "ck_$c"
  done
}

# ----------------------------------------------------------------------------
# exit swap (last)

cmd_swap() {
  need ENTRY_IP EXIT_IP EXIT2_IP
  local pins ep c tasks other
  write_hosts exit2 exit1
  if ap swap playbooks/swap-exit.yml; then
    touch "$STATE/swapped"
    c=$(recap swap entry1 changed)
    # Plays that touched the entry, directly or delegated (`[exit2 -> entry1(...)]`).
    tasks=$(awk '/^PLAY \[/ { p = $0; sub(/^PLAY \[/, "", p); sub(/\].*/, "", p) }
                 /^(ok|changed): \[entry1\]/ || /-> entry1[](]/ { print p }' "$LOGS/swap.log" | sort -u | paste -sd';' -)
    other=$(tr ';' '\n' <<<"$tasks" | grep -vxE "$SWAP_ENTRY_PLAYS")
    pins=$(on "$ENTRY_IP" "grep -F '$(awk '$1 == "exit_domain:" { print $2 }' "$INV/group_vars/all/vars.yml")' /etc/hosts")
    if reality; then # the entry's Xray talks to the new exit's REALITY port
      ep=$(on "$ENTRY_IP" "ss -tnH state established dst $EXIT2_IP:$(RPORT)" | awk '{print $4}' | head -n 1)
    else
      ep=$(on "$ENTRY_IP" 'docker exec multihop-uplink awg show awg-uplink endpoints' | awk '{print $2}')
    fi
    if [ "$c" = 0 ] && [ -z "$other" ] && [[ "$ep" == "$EXIT2_IP:"* ]]; then
      result PASS swap_exit "swap-exit.yml ok; entry changed=0; plays touching the entry: $tasks; hosts pin '$pins'; endpoint $ep"
    else
      result FAIL swap_exit "entry changed=$c; unexpected plays on the entry: '$other' (all: $tasks); endpoint $ep; pin '$pins'"
    fi
  else
    result FAIL swap_exit "swap-exit.yml failed, see $LOGS/swap.log"
  fi
  ck_first_run_reload swap  # exit.yml ran for the first time on EXIT2
  EXIT_NOW="$EXIT2_IP" cmd_check client_via_exit verify_fail_closed
}

# ----------------------------------------------------------------------------

cmd_clean() {
  need ENTRY_IP EXIT_IP
  local h
  for h in "$ENTRY_IP" "$EXIT_IP" ${EXIT2_IP:-} ${CLIENT_IP:-}; do
    on "$h" 'docker rm -f amnezia-awg2 amnezia-xray multihop-uplink multihop-uplink-xray multihop-exit multihop-exit-xray lab-client lab-xray-client 2>/dev/null;
      rm -rf /var/lib/multihop /var/lib/multihop-lab; echo "cleaned $(hostname)"' || true
  done
}

# ----------------------------------------------------------------------------
# entry swap (both branches). ENTRY2_IP is the other entry host; the VPN client
# runs on EXIT2_IP meanwhile and connects by entry_domain (hostsfile pin).

retire_host() { # retire_host <ip>: remove every multihop role and the lab client from a host
  on "$1" 'docker rm -f amnezia-awg2 amnezia-xray multihop-uplink multihop-uplink-xray multihop-exit multihop-exit-xray lab-client lab-xray-client >/dev/null 2>&1
    systemctl disable --now multihop-backup.timer multihop-reresolve.timer multihop-split-refresh.timer >/dev/null 2>&1
    systemctl stop multihop-net 2>/dev/null
    for s in multihop-exit-net multihop-entry-net; do [ -x /usr/local/sbin/$s ] && /usr/local/sbin/$s down; done
    systemctl disable multihop-net >/dev/null 2>&1
    rm -f /etc/systemd/system/multihop-net.service /etc/systemd/system/docker.service.d/multihop.conf \
      /etc/udev/rules.d/90-multihop-public-group.rules /usr/local/sbin/multihop-*
    rm -rf /var/lib/multihop /var/lib/multihop-lab /etc/multihop
    ip -o link show | awk -F": " "/group 51820/ {print \$2}" | while read -r i; do ip link set dev "$i" group default; done
    docker rmi amnezia-awg2 >/dev/null 2>&1
    systemctl daemon-reload; systemctl restart docker; echo "retired $(hostname)"'
}

write_hosts_entry_swap() { # <entry host> <entry_old host or ""> [<ansible_host override for entry2>]
  local e2="${3:-$ENTRY2_IP}" old=""
  [ -n "$2" ] && old="{hosts: {$2: {}}}"
  cat > "$INV/hosts.yml" <<EOF
---
# Generated by tests/integration/run.sh (entry swap). Do not commit.
all:
  vars:
    ansible_user: root
    ansible_ssh_private_key_file: $SSH_KEY
    ansible_ssh_common_args: -o IdentitiesOnly=yes -o UserKnownHostsFile=$KNOWN_HOSTS -o StrictHostKeyChecking=yes
  hosts:
    entry1: {ansible_host: $ENTRY_IP}
    entry2: {ansible_host: $e2}
    exit2: {ansible_host: $EXIT2_IP}
  children:
    entry: {hosts: {$1: {}}}
    entry_old: ${old:-"{}"}
    exit: {hosts: {exit2: {}}}
    exit_old: {}
    lab_client: {hosts: {exit2: {}}}
EOF
}

uplink_pub() { # public key in the lab vault_uplink.yml (not secret)
  uv run ansible-vault view "$INV/group_vars/all/vault_uplink.yml" 2>/dev/null | awk '$1 == "public_key:" { print $2 }'
}

client_on() { # client_on <entry ip>: restart the client (reconnect = re-resolve) and check where it goes
  local ep ip
  on "$CLIENT_IP" 'docker restart lab-client >/dev/null'
  wait_client || return 1
  ep=$(client awg show lab0 endpoints | awk '{print $2}')
  ip=$(client_curl https://api.ipify.org)
  echo "client endpoint $ep, egress $ip"
  [[ "$ep" == "$1:"* ]] && [ "$ip" = "$EXIT2_IP" ]
}

cmd_swap_entry() {
  need ENTRY_IP ENTRY2_IP EXIT2_IP
  [ -f "$STATE/swapped" ] || die "run the exit swap first (EXIT2 is the exit here)"
  CLIENT_IP="$EXIT2_IP"
  local pub ev ev2 fin rst a_state pin new old enc peers b_hs
  pub=$(client_pub)
  case "${1:-}" in
    reachable)  # entry1 (old) -> entry2 (new)
      log "retiring the exit role and the client on $ENTRY2_IP"; retire_host "$ENTRY2_IP"
      write_hosts_entry_swap entry1 ""
      ap swap-entry-client tests/integration/lab.yml --tags client || die "client on $EXIT2_IP failed"
      wait_client || die "client on $EXIT2_IP gets no traffic"
      write_hosts_entry_swap entry2 entry1
      ap swap-entry-pin tests/integration/lab.yml --tags pin,tools --skip-tags client || die "pin failed"
      if ! ap swap-entry-reachable playbooks/swap-entry.yml -e confirm=yes -v; then
        result FAIL swap_entry_reachable "swap-entry.yml failed, see $LOGS/swap-entry-reachable.log"; return
      fi
      fin=$(grep -o 'uploaded [^"\\ ]*' "$LOGS/swap-entry-reachable.log" | head -n 1 | sed 's/^uploaded //')
      rst=$(grep -o 'Restoring backup object [^"]*' "$LOGS/swap-entry-reachable.log" | head -n 1 | sed 's/^Restoring backup object //')
      a_state=$(on "$ENTRY_IP" "docker inspect -f '{{.Name}} running={{.State.Running}} restart={{.HostConfig.RestartPolicy.Name}}' amnezia-awg2 multihop-uplink | paste -sd' ' -; systemctl is-enabled multihop-backup.timer; systemctl is-active multihop-backup.timer" | paste -sd' ' -)
      pin=$(on "$EXIT2_IP" "grep -F entry.multihop.test /etc/hosts")
      ev=$(on "$ENTRY2_IP" "docker exec amnezia-awg2 awg show awg0 allowed-ips" | grep -F "$pub")
      ev2=$(client_on "$ENTRY2_IP"); local ok=$?
      if [ -n "$fin" ] && [ "$fin" = "$rst" ] && [[ "$a_state" == *"/amnezia-awg2 running=false restart=no /multihop-uplink running=false restart=no disabled inactive"* ]] \
         && [[ "$pin" == "$ENTRY2_IP "* ]] && [ -n "$ev" ] && [ "$ok" = 0 ]; then
        result PASS swap_entry_reachable "final backup $fin = restored object; old entry: $a_state; pin '$pin'; app-added peer on new entry ($ev); $ev2; verify (in playbook) ok"
      else
        result FAIL swap_entry_reachable "final '$fin' restored '$rst'; old entry '$a_state'; pin '$pin'; peer '$ev'; $ev2"
      fi ;;
    unreachable)  # entry2 (old, "unreachable") -> entry1 (new); the real entry2 keeps running
      old=$(uplink_pub)
      write_hosts_entry_swap entry1 entry2 192.0.2.1
      if ! ap swap-entry-unreachable playbooks/swap-entry.yml -e confirm=yes; then
        result FAIL swap_entry_unreachable "swap-entry.yml failed, see $LOGS/swap-entry-unreachable.log"; return
      fi
      new=$(uplink_pub)
      enc=$(head -c 14 "$INV/group_vars/all/vault_uplink.yml")
      peers=$(on "$EXIT2_IP" 'docker exec multihop-exit awg show awg-exit peers' | paste -sd' ' -)
      # The still-running old entry tries again with the old key: no handshake.
      b_hs=$(on "$ENTRY2_IP" 'docker restart multihop-uplink >/dev/null; for _ in $(seq 1 9); do sleep 5; echo kick > /dev/udp/10.9.0.1/9 2>/dev/null; done; docker exec multihop-uplink awg show awg-uplink latest-handshakes' | awk '{print $2}')
      pin=$(on "$EXIT2_IP" "grep -F entry.multihop.test /etc/hosts")
      ev=$(on "$ENTRY_IP" "docker exec amnezia-awg2 awg show awg0 allowed-ips" | grep -F "$pub")
      ev2=$(client_on "$ENTRY_IP"); local ok=$?
      if [ "$enc" = '$ANSIBLE_VAULT' ] && [ -n "$new" ] && [ "$new" != "$old" ] && [ "$peers" = "$new" ] \
         && [ "$b_hs" = 0 ] && [[ "$pin" == "$ENTRY_IP "* ]] && [ -n "$ev" ] && [ "$ok" = 0 ]; then
        result PASS swap_entry_unreachable "uplink key rotated ($old -> $new, vault_uplink.yml re-encrypted); exit peers: $new only; still-running old entry (old key) after 45 s: latest-handshake 0 (rejected); pin '$pin'; peer on new entry ($ev); $ev2; verify (in playbook) ok"
      else
        result FAIL swap_entry_unreachable "enc '$enc'; key $old -> $new; exit peers '$peers'; old entry handshake '$b_hs'; pin '$pin'; peer '$ev'; $ev2"
      fi ;;
    restore)  # back to the standard lab: entry1 entry, exit2 exit, client on ENTRY2 (EXIT_IP)
      log "retiring the old entry $ENTRY2_IP"; retire_host "$ENTRY2_IP"
      on "$EXIT2_IP" 'docker rm -f lab-client >/dev/null 2>&1; sed -i "/entry.multihop.test/d" /etc/hosts'
      CLIENT_IP="${LAB_CLIENT_IP:-$EXIT_IP}"
      write_hosts exit2 exit1
      ap swap-entry-restore tests/integration/lab.yml --tags tools,client || die "client back on $CLIENT_IP failed"
      wait_client && log "lab restored: entry $ENTRY_IP, exit $EXIT2_IP, client $CLIENT_IP" ;;
    *) die "usage: run.sh swap-entry reachable|unreachable|restore" ;;
  esac
}

case "${1:-}" in
  init) cmd_init ;;
  swap-entry) shift; cmd_swap_entry "$@" ;;
  deploy) cmd_deploy ;;
  client) cmd_client ;;
  check) shift; cmd_check "$@" ;;
  swap) cmd_swap ;;
  clean) cmd_clean ;;
  guard) echo "run.sh: no lab IP is a prod ansible_host" ;;
  *) sed -n '2,22p' "$0" >&2; exit 2 ;;
esac
