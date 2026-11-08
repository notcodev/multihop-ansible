load helpers

# Stateful fakes: iptables keeps one file per table.chain (rules as lines),
# ip keeps the rule list and table 51820 routes. Tests assert the end state.
setup() {
  export MULTIHOP_ENV="$BATS_TEST_TMPDIR/multihop.env"
  export MULTIHOP_RT_TABLES_DIR="$BATS_TEST_TMPDIR/rt_tables.d"
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  export IPT_DIR="$BATS_TEST_TMPDIR/ipt"
  export IP_DIR="$BATS_TEST_TMPDIR/ip"
  export IPT_GUARD="$BATS_TEST_TMPDIR/ipt_guard"
  cat > "$MULTIHOP_ENV" <<'ENV'
PUBLIC_IFACE=eth9
SSH_PORT=22
ENTRY_AWG_PORT=51470
BRIDGES="docker0 amn0"
ENV
  mkdir -p "$BATS_TEST_TMPDIR/bin" "$IPT_DIR" "$IP_DIR"
  # Built-in chains only: Docker is not running yet, DOCKER-USER is absent.
  touch "$IPT_DIR/filter.FORWARD" "$IPT_DIR/nat.POSTROUTING" \
        "$IPT_DIR/mangle.FORWARD" "$IPT_DIR/mangle.PREROUTING"
  cat > "$BATS_TEST_TMPDIR/bin/iptables" <<'STUB'
#!/bin/sh
echo "iptables $*" >> "$STUB_LOG"
d="$IPT_DIR"; t=filter
[ "$1" = -t ] && { t="$2"; shift 2; }
op="$1"; shift
f() { echo "$d/$t.$1"; }
case "$op" in
  -N) [ ! -f "$(f "$1")" ] || exit 1; : > "$(f "$1")" ;;
  -L) [ -f "$(f "$1")" ] ;;
  -F) [ -f "$(f "$1")" ] || exit 1; : > "$(f "$1")" ;;
  -X) [ -f "$(f "$1")" ] || exit 1
      ! cat "$d/$t".* | grep -q -E -e "(^| )-j $1\$" || exit 1; rm "$(f "$1")" ;;
  -E) [ -f "$(f "$1")" ] || exit 1; mv "$(f "$1")" "$(f "$2")"
      for x in "$d/$t".*; do sed -E "s/(^| )-j $1\$/\1-j $2/" "$x" > "$x.t"; mv "$x.t" "$x"; done ;;
  -S) if [ "$#" -eq 0 ]; then  # whole table
        for x in "$d/$t".*; do c="${x##*/$t.}"; echo "-N $c"; sed "s/^/-A $c /" "$x"; done
      else [ -f "$(f "$1")" ] || exit 1; echo "-N $1"; sed "s/^/-A $1 /" "$(f "$1")"; fi ;;
  -A|-I) c="$1"; shift; [ -f "$(f "$c")" ] || exit 1
      # like iptables, a jump to a user chain needs that chain to exist
      r="$*"; case " $r " in *" -j MULTIHOP-"*) j="${r##*-j }"; [ -f "$(f "${j%% *}")" ] || exit 1 ;; esac
      if [ "$op" = -A ]; then echo "$*" >> "$(f "$c")"
      else { echo "$*"; cat "$(f "$c")"; } > "$(f "$c").t"; mv "$(f "$c").t" "$(f "$c")"; fi ;;
  -C) c="$1"; shift; [ -f "$(f "$c")" ] && grep -qxF -e "$*" "$(f "$c")" ;;
  -D) c="$1"; shift; grep -qxF -e "$*" "$(f "$c")" || exit 1
      awk -v t="$*" '$0==t && !done {done=1; next} {print}' "$(f "$c")" > "$(f "$c").t"; mv "$(f "$c").t" "$(f "$c")" ;;
  *) exit 9 ;;
esac
rc=$?
# Guard: when $IPT_GUARD lists bridges, every filter -D/-F/-X must leave
# DOCKER-USER jumping to a chain that drops everything else from each bridge.
# The guard arms itself once that holds, so it can be set before the first up.
if [ "$t" = filter ] && [ -f "$IPT_GUARD" ]; then
  ok=
  for j in $(sed -n 's/^-j //p' "$d/filter.DOCKER-USER" 2>/dev/null); do
    all=1
    for br in $(cat "$IPT_GUARD"); do
      grep -qxF -e "-i $br -j DROP" "$d/filter.$j" 2>/dev/null || all=
    done
    [ -n "$all" ] && ok=1
  done
  if [ -n "$ok" ]; then : > "$IPT_GUARD.armed"
  elif [ -f "$IPT_GUARD.armed" ]; then
    case "$op" in -D|-F|-X)
      echo "iptables -t filter $op $* left DOCKER-USER without backstop" >> "$IPT_GUARD.violations"
    esac
  fi
fi
# Guard: every MULTIHOP-TPROXY* chain that a chain jumped to from PREROUTING
# references exists and ends in DROP (never an empty or half-built chain), and
# such a chain that direct-marks has the force_exit rule (RETURN in awg mode,
# a jump to MULTIHOP-TPROXY* in reality mode) ahead of the direct mark, so a
# force_exit address in the direct set is never let out the public interface.
# Once every listed bridge has a PREROUTING jump into MULTIHOP-MARK*, a
# -D/-F/-X/-E must leave each with one (no window without reply/direct marks).
if [ "$t" = mangle ] && [ -f "$IPT_GUARD" ]; then
  for c in $(sed -n 's/.*-j \(MULTIHOP-[A-Z-]*\)$/\1/p' "$d/mangle.PREROUTING"); do
    for j in $(sed -n 's/.*-j \(MULTIHOP-TPROXY[A-Z-]*\)$/\1/p' "$d/mangle.$c" 2>/dev/null); do
      [ "$(tail -n1 "$d/mangle.$j" 2>/dev/null)" = "-j DROP" ] \
        || echo "iptables -t mangle $op $* left $c jumping to an incomplete $j" >> "$IPT_GUARD.violations"
    done
    dm=$(grep -n -m1 -e '--match-set multihop_direct dst -j MARK' "$d/mangle.$c" 2>/dev/null | cut -d: -f1)
    fe=$(grep -n -m1 -E -e '--match-set multihop_force_exit dst -j (RETURN|MULTIHOP-TPROXY[A-Z-]*)$' "$d/mangle.$c" 2>/dev/null | cut -d: -f1)
    if [ -n "$dm" ] && { [ -z "$fe" ] || [ "$fe" -gt "$dm" ]; }; then
      echo "iptables -t mangle $op $* left $c (from PREROUTING) direct-marking without force_exit first" >> "$IPT_GUARD.violations"
    fi
  done
  all=1
  for br in $(cat "$IPT_GUARD"); do
    grep -qE -e "^-i $br -j MULTIHOP-MARK(-NEW)?\$" "$d/mangle.PREROUTING" || all=
  done
  if [ -n "$all" ]; then : > "$IPT_GUARD.mark-armed"
  elif [ -f "$IPT_GUARD.mark-armed" ]; then
    case "$op" in -D|-F|-X|-E)
      echo "iptables -t mangle $op $* left a bridge without a PREROUTING jump into MULTIHOP-MARK" >> "$IPT_GUARD.violations"
    esac
  fi
fi
exit $rc
STUB
  # Fake ip. When $IP_DIR/guard lists bridges, every rule deletion checks that
  # each of them still has a rule into table 51820 (no fall-through to main).
  cat > "$BATS_TEST_TMPDIR/bin/ip" <<'STUB'
#!/bin/sh
echo "ip $*" >> "$STUB_LOG"
d="$IP_DIR"; touch "$d/rules" "$d/routes"
case "$1 $2" in
  "rule add")
    shift 2; [ "$1" = pref ] || exit 9
    line="$2"; shift 2; line="$line $*"
    if grep -qxF -e "$line" "$d/rules"; then echo "RTNETLINK answers: File exists" >&2; exit 2; fi
    echo "$line" >> "$d/rules" ;;
  "rule del")
    shift 2; { [ "$1" = pref ] && [ $# -eq 2 ]; } || exit 9
    grep -q "^$2 " "$d/rules" || { echo "RTNETLINK answers: No such file or directory" >&2; exit 2; }
    awk -v p="$2" '$1==p && !done {done=1; next} {print}' "$d/rules" > "$d/rules.t"; mv "$d/rules.t" "$d/rules"
    if [ -f "$d/guard" ]; then
      for br in $(cat "$d/guard"); do
        grep -q " iif $br lookup 51820\$" "$d/rules" || echo "ip rule del pref $2 left $br uncovered" >> "$d/violations"
      done
    fi ;;
  "route replace")
    shift 2; line="$*"
    { grep -vxF -e "$line" "$d/routes"; echo "$line"; } > "$d/routes.t"; mv "$d/routes.t" "$d/routes" ;;
  "route del")
    shift 2; line="$*"; grep -qxF -e "$line" "$d/routes" || exit 2
    grep -vxF -e "$line" "$d/routes" > "$d/routes.t"; mv "$d/routes.t" "$d/routes" ;;
  "link set")
    [ "$3 $5" = "dev group" ] || exit 9
    echo "$4 group $6" > "$d/link.$4" ;;
  *) exit 9 ;;
esac
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/iptables" "$BATS_TEST_TMPDIR/bin/ip"
  stub ipset
  stub ip6tables "" 1
  : > "$STUB_LOG"
}

# Line number of the first stub-log line matching the regex.
first_line() { grep -n -m1 -e "$1" "$STUB_LOG" | cut -d: -f1; }

expected_rules() {
  cat <<'R'
10100 fwmark 0x5a/0xff lookup main
10110 fwmark 0x5b00/0xff00 lookup main
10120 iif docker0 lookup main suppress_prefixlength 0 suppress_ifgroup 51820
10120 iif amn0 lookup main suppress_prefixlength 0 suppress_ifgroup 51820
10130 iif docker0 lookup 51820
10130 iif amn0 lookup 51820
R
}

# Allow-list per bridge: uplink, the bridges, and out the public interface
# only direct-marked or AWG UDP; everything else (e.g. a provider private
# network on another NIC) is dropped.
expected_fwd() {
  cat <<'R'
-i docker0 -o awg-uplink -j RETURN
-i docker0 -o docker0 -j RETURN
-i docker0 -o amn0 -j RETURN
-i docker0 -o eth9 -m mark --mark 0x5a/0xff -j RETURN
-i docker0 -o eth9 -p udp --sport 51470 -j RETURN
-i amn0 -o awg-uplink -j RETURN
-i amn0 -o docker0 -j RETURN
-i amn0 -o amn0 -j RETURN
-i amn0 -o eth9 -m mark --mark 0x5a/0xff -j RETURN
-i amn0 -o eth9 -p udp --sport 51470 -j RETURN
-i docker0 -j DROP
-i amn0 -j DROP
R
}

# Snapshot of every iptables chain and the ip state, for convergence checks.
snapshot() {
  for x in "$IPT_DIR"/* "$IP_DIR/rules" "$IP_DIR/routes"; do
    echo "== ${x##*/}"; cat "$x"
  done
}

@test "rules have priorities 10100..10130 for both bridges" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") <(expected_rules)
}

# Providers install DHCP host routes (e.g. to their resolvers) via the public
# interface; bridge traffic must not take them (dropped by the backstop, so
# DNS from containers failed) but go through the uplink like the default route.
@test "public interface is grouped before rule 10120 suppresses its group" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IP_DIR/link.eth9")" = "eth9 group 51820" ]
  grp=$(first_line '^ip link set dev eth9 group 51820$')
  r=$(first_line '^ip rule add pref 10120 .*suppress_ifgroup 51820$')
  [ -n "$grp" ] && [ -n "$r" ] && [ "$grp" -lt "$r" ]
}

@test "a missing public interface does not stop the rules" {
  cat > "$BATS_TEST_TMPDIR/bin/ip.real" < "$BATS_TEST_TMPDIR/bin/ip"
  cat > "$BATS_TEST_TMPDIR/bin/ip" <<STUB
#!/bin/sh
[ "\$1 \$2" = "link set" ] && { echo "ip \$*" >> "\$STUB_LOG"; echo 'Cannot find device "eth9"' >&2; exit 1; }
exec sh "$BATS_TEST_TMPDIR/bin/ip.real" "\$@"
STUB
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  grep -qF "cannot set the group of eth9" <<<"$output"
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") <(expected_rules)
}

@test "blackhole default in table 51820" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IP_DIR/routes")" = "blackhole default metric 4096 table 51820" ]
  # the blackhole exists before any rule can send traffic to table 51820,
  # so an empty table never falls through to main
  bh=$(first_line '^ip route replace blackhole default metric 4096 table 51820$')
  r=$(first_line '^ip rule add .*lookup 51820$')
  [ -n "$bh" ] && [ -n "$r" ] && [ "$bh" -lt "$r" ]
}

@test "routing table name is registered" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$MULTIHOP_RT_TABLES_DIR/multihop.conf")" = "51820 multihop" ]
}

@test "MULTIHOP-FWD allow-lists per bridge and drops the rest last" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff "$IPT_DIR/filter.MULTIHOP-FWD" <(expected_fwd)
  [ "$(tail -n1 "$IPT_DIR/filter.MULTIHOP-FWD")" = "-i amn0 -j DROP" ]
  # no DROP is limited to an output interface: other NICs are covered too
  ! grep -e '-o .* -j DROP' "$IPT_DIR/filter.MULTIHOP-FWD" || false
  [ "$(cat "$IPT_DIR/filter.DOCKER-USER")" = "-j MULTIHOP-FWD" ]
}

@test "direct mark and awg reply are allowed before drop" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  for br in docker0 amn0; do
    f="$IPT_DIR/filter.MULTIHOP-FWD"
    mark=$(grep -n -x -e "-i $br -o eth9 -m mark --mark 0x5a/0xff -j RETURN" "$f" | cut -d: -f1)
    reply=$(grep -n -x -e "-i $br -o eth9 -p udp --sport 51470 -j RETURN" "$f" | cut -d: -f1)
    drop=$(grep -n -x -e "-i $br -j DROP" "$f" | cut -d: -f1)
    [ -n "$mark" ] && [ -n "$reply" ] && [ -n "$drop" ]
    [ "$mark" -lt "$drop" ] && [ "$reply" -lt "$drop" ]
  done
  # out the public interface nothing else is let through
  [ "$(grep -c -e '-o eth9 .*-j RETURN' "$IPT_DIR/filter.MULTIHOP-FWD")" -eq 4 ]
}

@test "force_exit RETURN precedes direct MARK" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff "$IPT_DIR/mangle.MULTIHOP-MARK" - <<'R'
-p udp --sport 51470 -j MARK --set-mark 0x5b00/0xff00
-m set --match-set multihop_force_exit dst -j RETURN
-m set --match-set multihop_direct dst -j MARK --set-mark 0x5a/0xff
R
  diff <(sort "$IPT_DIR/mangle.PREROUTING") - <<'R'
-i amn0 -j MULTIHOP-MARK
-i docker0 -j MULTIHOP-MARK
R
  # both sets exist (empty if new) before the rules reference them, and
  # creating them does not delay the backstop
  fwd=$(first_line '^iptables -t filter -I DOCKER-USER -j MULTIHOP-FWD-NEW$')
  for s in multihop_direct multihop_force_exit; do
    n=$(first_line "^ipset create $s hash:net -exist\$")
    [ -n "$n" ] && [ "$n" -lt "$(first_line '^iptables -t mangle -A MULTIHOP-MARK-NEW')" ]
    [ "$n" -gt "$fwd" ]
  done
}

@test "awg traffic is marked by source port and routed by the reply mark" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  # UDP from the AWG port gets the reply mark in both conntrack directions
  # (the app container keeps user UDP off that port, see entry_app start.sh)
  [ "$(head -n1 "$IPT_DIR/mangle.MULTIHOP-MARK")" = "-p udp --sport 51470 -j MARK --set-mark 0x5b00/0xff00" ]
  ! grep -q -e conntrack "$IPT_DIR/mangle.MULTIHOP-MARK" "$IPT_DIR/filter.MULTIHOP-FWD" || false
  # routing exception keys on that mark only
  grep -qx -e '10110 fwmark 0x5b00/0xff00 lookup main' "$IP_DIR/rules"
  ! grep -q -e 'sport\|ipproto' "$IP_DIR/rules" || false
  # backstop lets exactly that through, per bridge, to the public iface only
  [ "$(grep -c -e '--sport' "$IPT_DIR/filter.MULTIHOP-FWD")" -eq 2 ]
  grep -qx -e '-i docker0 -o eth9 -p udp --sport 51470 -j RETURN' "$IPT_DIR/filter.MULTIHOP-FWD"
  grep -qx -e '-i amn0 -o eth9 -p udp --sport 51470 -j RETURN' "$IPT_DIR/filter.MULTIHOP-FWD"
  # reply mark and direct mark use disjoint mask bytes
  ! grep -q -e '0x5b00/0xff ' "$IPT_DIR/mangle.MULTIHOP-MARK" || false
}

@test "nat and mss clamp on awg-uplink" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/nat.MULTIHOP-NAT")" = "-o awg-uplink -j MASQUERADE" ]
  [ "$(cat "$IPT_DIR/nat.POSTROUTING")" = "-j MULTIHOP-NAT" ]
  [ "$(cat "$IPT_DIR/mangle.MULTIHOP-MSS")" = "-o awg-uplink -p tcp --tcp-flags SYN,RST SYN -j TCPMSS --clamp-mss-to-pmtu" ]
  [ "$(cat "$IPT_DIR/mangle.FORWARD")" = "-j MULTIHOP-MSS" ]
}

@test "DOCKER-USER is created and jumped to before docker runs" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/filter.FORWARD")" = "-j DOCKER-USER" ]
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/filter.FORWARD")" = "-j DOCKER-USER" ]
}

@test "existing DOCKER-USER rules and jump are kept" {
  echo "-j DOCKER-USER" > "$IPT_DIR/filter.FORWARD"
  echo "-j RETURN" > "$IPT_DIR/filter.DOCKER-USER"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ "$(cat "$IPT_DIR/filter.FORWARD")" = "-j DOCKER-USER" ]
  [ "$(cat "$IPT_DIR/filter.DOCKER-USER")" = "$(printf -- '-j MULTIHOP-FWD\n-j RETURN')" ]
}

@test "backstop is installed before ip rules are touched" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  fwd=$(first_line '^iptables -t filter -I DOCKER-USER -j MULTIHOP-FWD-NEW$')
  rule=$(first_line '^ip rule ')
  [ -n "$fwd" ] && [ -n "$rule" ] && [ "$fwd" -lt "$rule" ]
}

@test "ipv6 forwarding from bridges is dropped" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  grep -qx -e 'ip6tables -I FORWARD -i docker0 -j DROP' "$STUB_LOG"
  grep -qx -e 'ip6tables -I FORWARD -i amn0 -j DROP' "$STUB_LOG"
}

@test "ipv6 drop is not duplicated when already present" {
  stub ip6tables "" 0   # -C succeeds: rule present
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  ! grep -q -e '^ip6tables -I' "$STUB_LOG" || false
}

@test "missing ip6tables is tolerated" {
  stub ip6tables "" 127
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
}

@test "up twice yields no duplicate ip rules" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  before=$(snapshot)
  echo "docker0 amn0" > "$IP_DIR/guard"
  echo "docker0 amn0" > "$IPT_GUARD"
  : > "$STUB_LOG"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  # every priority is cleared before it is re-added
  for p in 10100 10110 10120 10130; do
    del=$(first_line "^ip rule del pref $p\$")
    add=$(first_line "^ip rule add pref $p ")
    [ -n "$del" ] && [ -n "$add" ] && [ "$del" -lt "$add" ]
  done
  # bridge traffic was never left without a rule into table 51820, and
  # DOCKER-USER never without the bridge -> public DROP
  [ ! -f "$IP_DIR/violations" ]
  [ ! -f "$IPT_GUARD.violations" ]
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") <(expected_rules)
  # whole state (iptables and ip) converged to exactly the same set
  [ "$(snapshot)" = "$before" ]
  ! ls "$IPT_DIR" | grep -e '-NEW' || false
}

@test "changed port and bridges drop stale rules" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  cat > "$MULTIHOP_ENV" <<'ENV'
PUBLIC_IFACE=eth9
ENTRY_AWG_PORT=40000
BRIDGES="docker0"
ENV
  echo "docker0" > "$IP_DIR/guard"
  echo "docker0" > "$IPT_GUARD"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  [ ! -f "$IP_DIR/violations" ]
  [ ! -f "$IPT_GUARD.violations" ]
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") - <<'R'
10100 fwmark 0x5a/0xff lookup main
10110 fwmark 0x5b00/0xff00 lookup main
10120 iif docker0 lookup main suppress_prefixlength 0 suppress_ifgroup 51820
10130 iif docker0 lookup 51820
R
  ! grep -q amn0 "$IPT_DIR/filter.MULTIHOP-FWD" "$IPT_DIR/mangle.PREROUTING" || false
  ! grep -q 51470 "$IPT_DIR/filter.MULTIHOP-FWD" "$IPT_DIR/mangle.MULTIHOP-MARK" || false
  grep -qx -e '-i docker0 -o eth9 -p udp --sport 40000 -j RETURN' "$IPT_DIR/filter.MULTIHOP-FWD"
}

@test "down removes rules, routes and chains" {
  run_script multihop-entry-net up
  run_script multihop-entry-net down
  [ "$status" -eq 0 ]
  [ ! -s "$IP_DIR/rules" ]
  [ ! -s "$IP_DIR/routes" ]
  [ "$(cat "$IP_DIR/link.eth9")" = "eth9 group default" ]
  [ ! -s "$IPT_DIR/filter.DOCKER-USER" ]
  [ ! -s "$IPT_DIR/mangle.PREROUTING" ]
  [ ! -s "$IPT_DIR/nat.POSTROUTING" ]
  [ ! -s "$IPT_DIR/mangle.FORWARD" ]
  ! ls "$IPT_DIR" | grep -e MULTIHOP || false
}

@test "unknown command fails" {
  run_script multihop-entry-net sideways
  [ "$status" -eq 2 ]
}

# --- reality mode (TPROXY into the local Xray) and the Xray reply exception.
# Exact rules: docs/superpowers/specs/2026-11-03-xray-only-uplink-addendum.md
# section 3.

# env_with <key=value...>: the base env plus the given keys.
env_with() {
  cat > "$MULTIHOP_ENV" <<'ENV'
PUBLIC_IFACE=eth9
SSH_PORT=22
ENTRY_AWG_PORT=51470
BRIDGES="docker0 amn0"
ENV
  printf '%s\n' "$@" >> "$MULTIHOP_ENV"
}

reality_env() {
  env_with UPLINK_TRANSPORT=reality ENTRY_XRAY_PORT=443 UPLINK_TPROXY_PORT=12345 \
    'ENTRY_LOCAL_NETS="172.17.0.0/16 172.29.172.0/24"'
}

awg_xray_env() {
  env_with UPLINK_TRANSPORT=awg ENTRY_XRAY_PORT=443 UPLINK_TPROXY_PORT=12345 \
    'ENTRY_LOCAL_NETS="172.17.0.0/16 172.29.172.0/24"'
}

# Both guards on from the first up: the iptables one arms itself once the
# backstop exists; the ip one only once every bridge has its 51820 rule.
guard_on() {
  echo "docker0 amn0" > "$IPT_GUARD"
}

no_violations() {
  [ ! -f "$IPT_GUARD.violations" ] || { cat "$IPT_GUARD.violations"; false; }
  [ ! -f "$IP_DIR/violations" ] || { cat "$IP_DIR/violations"; false; }
}

expected_reality_mark() {
  cat <<'R'
-p udp --sport 51470 -j MARK --set-mark 0x5b00/0xff00
-p tcp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport 443 -j MARK --set-mark 0x5b00/0xff00
-p udp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport 443 -j MARK --set-mark 0x5b00/0xff00
-m mark --mark 0x5b00/0xff00 -j RETURN
-m set --match-set multihop_force_exit dst -j MULTIHOP-TPROXY
-m set --match-set multihop_direct dst -j MARK --set-mark 0x5a/0xff
-m mark --mark 0x5a/0xff -j CONNMARK --save-mark --nfmask 0xff --ctmask 0xff
-m mark --mark 0x5a/0xff -j RETURN
-j MULTIHOP-TPROXY
R
}

expected_tproxy() {
  cat <<'R'
-m addrtype --dst-type LOCAL -j RETURN
-d 172.17.0.0/16 -j RETURN
-d 172.29.172.0/24 -j RETURN
-p tcp -j TPROXY --on-ip 127.0.0.1 --on-port 12345
-p udp -j TPROXY --on-ip 127.0.0.1 --on-port 12345
-j DROP
R
}

expected_awg_xray_mark() {
  cat <<'R'
-p udp --sport 51470 -j MARK --set-mark 0x5b00/0xff00
-p tcp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport 443 -j MARK --set-mark 0x5b00/0xff00
-p udp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport 443 -j MARK --set-mark 0x5b00/0xff00
-m set --match-set multihop_force_exit dst -j RETURN
-m set --match-set multihop_direct dst -j MARK --set-mark 0x5a/0xff
R
}

expected_xray_fwd() {
  cat <<'R'
-i docker0 -o awg-uplink -j RETURN
-i docker0 -o docker0 -j RETURN
-i docker0 -o amn0 -j RETURN
-i docker0 -o eth9 -m mark --mark 0x5a/0xff -j RETURN
-i docker0 -o eth9 -p udp --sport 51470 -j RETURN
-i docker0 -o eth9 -p tcp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport 443 -j RETURN
-i docker0 -o eth9 -p udp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport 443 -j RETURN
-i amn0 -o awg-uplink -j RETURN
-i amn0 -o docker0 -j RETURN
-i amn0 -o amn0 -j RETURN
-i amn0 -o eth9 -m mark --mark 0x5a/0xff -j RETURN
-i amn0 -o eth9 -p udp --sport 51470 -j RETURN
-i amn0 -o eth9 -p tcp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport 443 -j RETURN
-i amn0 -o eth9 -p udp -m conntrack --ctstate DNAT --ctdir REPLY --ctorigdstport 443 -j RETURN
-i docker0 -j DROP
-i amn0 -j DROP
R
}

# The awg end state: no local route, no TPROXY chain, nothing staged.
assert_awg_state() {
  [ "$(cat "$IP_DIR/routes")" = "blackhole default metric 4096 table 51820" ]
  [ ! -e "$IPT_DIR/mangle.MULTIHOP-TPROXY" ]
  [ ! -e "$IPT_DIR/mangle.MULTIHOP-INGRESS" ]
  ! ls "$IPT_DIR" | grep -e '-NEW' || false
  ! grep -rq -e TPROXY "$IPT_DIR" || false
}

assert_reality_state() {
  diff <(sort "$IP_DIR/routes") - <<'R'
blackhole default metric 4096 table 51820
local default dev lo table 51820
R
  diff "$IPT_DIR/mangle.MULTIHOP-MARK" <(expected_reality_mark)
  diff "$IPT_DIR/mangle.MULTIHOP-TPROXY" <(expected_tproxy)
  diff <(sort "$IPT_DIR/mangle.PREROUTING") - <<'R'
-i amn0 -j MULTIHOP-MARK
-i docker0 -j MULTIHOP-MARK
-i eth9 -m addrtype --dst-type LOCAL -j MULTIHOP-INGRESS
R
  ! ls "$IPT_DIR" | grep -e '-NEW' || false
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") <(expected_rules)
}

@test "reality: table 51820 has local default and blackhole" {
  reality_env; guard_on
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff <(sort "$IP_DIR/routes") - <<'R'
blackhole default metric 4096 table 51820
local default dev lo table 51820
R
  # both routes exist before any rule can send traffic to table 51820
  r=$(first_line '^ip rule add .*lookup 51820$')
  for re in '^ip route replace blackhole default metric 4096 table 51820$' \
            '^ip route replace local default dev lo table 51820$'; do
    n=$(first_line "$re")
    [ -n "$n" ] && [ -n "$r" ] && [ "$n" -lt "$r" ]
  done
  # the ip rules themselves are unchanged
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") <(expected_rules)
  no_violations
}

@test "reality: MULTIHOP-MARK has the addendum layout in order" {
  reality_env; guard_on
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff "$IPT_DIR/mangle.MULTIHOP-MARK" <(expected_reality_mark)
  diff <(sort "$IPT_DIR/mangle.PREROUTING") - <<'R'
-i amn0 -j MULTIHOP-MARK
-i docker0 -j MULTIHOP-MARK
-i eth9 -m addrtype --dst-type LOCAL -j MULTIHOP-INGRESS
R
  no_violations
}

@test "reality: mark public VPN ingress before local routing for reverse source validation" {
  reality_env; guard_on
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff "$IPT_DIR/mangle.MULTIHOP-INGRESS" - <<'R'
-p udp --dport 51470 -j MARK --set-mark 0x5b00/0xff00
-p tcp --dport 443 -j MARK --set-mark 0x5b00/0xff00
-p udp --dport 443 -j MARK --set-mark 0x5b00/0xff00
-m conntrack --ctdir REPLY -m connmark --mark 0x5a/0xff -j CONNMARK --restore-mark --nfmask 0xff --ctmask 0xff
R
  ingress=$(first_line '^iptables -t mangle -I PREROUTING -i eth9 -m addrtype --dst-type LOCAL -j MULTIHOP-INGRESS-NEW$')
  route=$(first_line '^ip route replace local default dev lo table 51820$')
  [ -n "$ingress" ] && [ "$ingress" -lt "$route" ]
  no_violations

  # A disabled app Xray must not grant a bypass to that port.
  env_with UPLINK_TRANSPORT=reality ENTRY_XRAY_PORT= 'ENTRY_LOCAL_NETS="172.17.0.0/16"'
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff "$IPT_DIR/mangle.MULTIHOP-INGRESS" - <<'R'
-p udp --dport 51470 -j MARK --set-mark 0x5b00/0xff00
-m conntrack --ctdir REPLY -m connmark --mark 0x5a/0xff -j CONNMARK --restore-mark --nfmask 0xff --ctmask 0xff
R
  no_violations
}

@test "reality: MULTIHOP-TPROXY rules exact and installed before MULTIHOP-MARK references it" {
  reality_env; guard_on
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  diff "$IPT_DIR/mangle.MULTIHOP-TPROXY" <(expected_tproxy)
  # the new TPROXY chain is complete before any MARK rule jumps to it, and
  # MARK is jumped to from PREROUTING only after that
  done_tp=$(first_line '^iptables -t mangle -A MULTIHOP-TPROXY-NEW -j DROP$')
  ref=$(first_line '^iptables -t mangle -A MULTIHOP-MARK-NEW .*-j MULTIHOP-TPROXY')
  jump=$(first_line '^iptables -t mangle -I PREROUTING -i docker0 -j MULTIHOP-MARK-NEW$')
  [ -n "$done_tp" ] && [ -n "$ref" ] && [ -n "$jump" ]
  [ "$done_tp" -lt "$ref" ] && [ "$ref" -lt "$jump" ]
  # backstop still first
  fwd=$(first_line '^iptables -t filter -I DOCKER-USER -j MULTIHOP-FWD-NEW$')
  [ "$fwd" -lt "$(first_line '^iptables -t mangle -N MULTIHOP-TPROXY-NEW$')" ]
  no_violations
}

@test "reality: up twice converges and retires the old TPROXY chain after the new MARK" {
  reality_env; guard_on
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  before=$(snapshot)
  echo "docker0 amn0" > "$IP_DIR/guard"
  : > "$STUB_LOG"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  no_violations
  [ "$(snapshot)" = "$before" ]
  assert_reality_state
  swap=$(first_line '^iptables -t mangle -E MULTIHOP-MARK-NEW MULTIHOP-MARK$')
  old=$(first_line '^iptables -t mangle -X MULTIHOP-TPROXY$')
  ren=$(first_line '^iptables -t mangle -E MULTIHOP-TPROXY-NEW MULTIHOP-TPROXY$')
  [ -n "$swap" ] && [ -n "$old" ] && [ -n "$ren" ]
  [ "$swap" -lt "$old" ] && [ "$old" -lt "$ren" ]
}

# --- an `up` interrupted mid-swap (seeded state) is completed, not undone.
# seed_mark_chain <file> <tproxy chain>: the reality MARK layout jumping to it.
seed_mark_chain() {
  expected_reality_mark | sed -E "s/-j MULTIHOP-TPROXY$/-j $2/" > "$1"
}

# The old TPROXY chain (another port) and the new one, complete.
seed_tproxy_chains() {
  expected_tproxy | sed 's/12345/11111/' > "$IPT_DIR/mangle.MULTIHOP-TPROXY"
  expected_tproxy > "$IPT_DIR/mangle.MULTIHOP-TPROXY-NEW"
}

seed_prerouting() { # seed_prerouting <chain>
  printf -- '-i docker0 -j %s\n-i amn0 -j %s\n' "$1" "$1" > "$IPT_DIR/mangle.PREROUTING"
}

@test "reality: up after one interrupted between the MARK retire and rename completes the swap" {
  reality_env
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  # interrupted in install_chain after the old MARK was dropped: PREROUTING
  # jumps to MARK-NEW only, which jumps to the (complete) TPROXY-NEW
  rm "$IPT_DIR/mangle.MULTIHOP-MARK"
  seed_tproxy_chains
  seed_mark_chain "$IPT_DIR/mangle.MULTIHOP-MARK-NEW" MULTIHOP-TPROXY-NEW
  seed_prerouting MULTIHOP-MARK-NEW
  guard_on; echo "docker0 amn0" > "$IP_DIR/guard"
  : > "$STUB_LOG"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  no_violations
  assert_reality_state
  # the staged chains were renamed, not dropped from PREROUTING
  ren=$(first_line '^iptables -t mangle -E MULTIHOP-MARK-NEW MULTIHOP-MARK$')
  [ -n "$ren" ] && [ "$ren" -lt "$(first_line '^iptables -t mangle -D PREROUTING')" ]
}

@test "reality: up after one interrupted between the MARK swap and the TPROXY rename completes it" {
  local gone
  for gone in keep drop; do
    reality_env
    rm -f "$IPT_DIR"/* "$IP_DIR"/* "$IPT_GUARD".*
    touch "$IPT_DIR/filter.FORWARD" "$IPT_DIR/nat.POSTROUTING" \
          "$IPT_DIR/mangle.FORWARD" "$IPT_DIR/mangle.PREROUTING"
    run_script multihop-entry-net up
    [ "$status" -eq 0 ]
    # the new MARK is live and jumps to TPROXY-NEW; the old TPROXY is
    # unreferenced (kept, or already dropped)
    seed_tproxy_chains
    [ "$gone" = keep ] || rm "$IPT_DIR/mangle.MULTIHOP-TPROXY"
    seed_mark_chain "$IPT_DIR/mangle.MULTIHOP-MARK" MULTIHOP-TPROXY-NEW
    seed_prerouting MULTIHOP-MARK
    guard_on; echo "docker0 amn0" > "$IP_DIR/guard"
    : > "$STUB_LOG"
    run_script multihop-entry-net up
    echo "old TPROXY $gone: $output"
    [ "$status" -eq 0 ]
    no_violations
    assert_reality_state
    ! grep -q -e '11111' "$IPT_DIR/mangle.MULTIHOP-TPROXY" || false
    # the live MARK's jumps to TPROXY-NEW were never stripped
    ! grep -q -e '^iptables -t mangle -D MULTIHOP-MARK ' "$STUB_LOG" || false
  done
}

@test "awg: up after one interrupted between the MARK retire and rename completes the swap" {
  awg_xray_env
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  mv "$IPT_DIR/mangle.MULTIHOP-MARK" "$IPT_DIR/mangle.MULTIHOP-MARK-NEW"
  seed_prerouting MULTIHOP-MARK-NEW
  guard_on; echo "docker0 amn0" > "$IP_DIR/guard"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  no_violations
  assert_awg_state
  diff "$IPT_DIR/mangle.MULTIHOP-MARK" <(expected_awg_xray_mark)
}

@test "up after one interrupted between the MULTIHOP-FWD retire and rename keeps the backstop" {
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  mv "$IPT_DIR/filter.MULTIHOP-FWD" "$IPT_DIR/filter.MULTIHOP-FWD-NEW"
  echo "-j MULTIHOP-FWD-NEW" > "$IPT_DIR/filter.DOCKER-USER"
  guard_on; echo "docker0 amn0" > "$IP_DIR/guard"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  no_violations
  diff "$IPT_DIR/filter.MULTIHOP-FWD" <(expected_fwd)
  [ "$(cat "$IPT_DIR/filter.DOCKER-USER")" = "-j MULTIHOP-FWD" ]
}

@test "awg: no local route, no MULTIHOP-TPROXY, MULTIHOP-MARK as today plus xray reply rules when ENTRY_XRAY_PORT set" {
  awg_xray_env; guard_on
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  assert_awg_state
  diff "$IPT_DIR/mangle.MULTIHOP-MARK" <(expected_awg_xray_mark)
  diff <(sort -s -n -k1,1 "$IP_DIR/rules") <(expected_rules)
  no_violations
}

@test "awg is the default transport" {
  env_with 'ENTRY_LOCAL_NETS="172.17.0.0/16"'
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  assert_awg_state
}

@test "switch reality -> awg removes local route and MULTIHOP-TPROXY" {
  reality_env; guard_on
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  echo "docker0 amn0" > "$IP_DIR/guard"
  awg_xray_env
  : > "$STUB_LOG"
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  no_violations
  assert_awg_state
  diff "$IPT_DIR/mangle.MULTIHOP-MARK" <(expected_awg_xray_mark)
  # MARK without the jumps is swapped in before TPROXY is dropped
  swap=$(first_line '^iptables -t mangle -E MULTIHOP-MARK-NEW MULTIHOP-MARK$')
  drop=$(first_line '^iptables -t mangle -X MULTIHOP-TPROXY$')
  [ -n "$swap" ] && [ -n "$drop" ] && [ "$swap" -lt "$drop" ]
}

@test "switch awg -> reality adds them" {
  awg_xray_env; guard_on
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  echo "docker0 amn0" > "$IP_DIR/guard"
  reality_env
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  no_violations
  assert_reality_state
}

@test "xray reply exception in MULTIHOP-FWD before the bridge DROP lines; absent when ENTRY_XRAY_PORT empty" {
  for mode in reality awg; do
    env_with "UPLINK_TRANSPORT=$mode" ENTRY_XRAY_PORT=443 'ENTRY_LOCAL_NETS="172.17.0.0/16 172.29.172.0/24"'
    guard_on
    run_script multihop-entry-net up
    [ "$status" -eq 0 ]
    diff "$IPT_DIR/filter.MULTIHOP-FWD" <(expected_xray_fwd)
    no_violations
  done
  for mode in reality awg; do
    env_with "UPLINK_TRANSPORT=$mode" ENTRY_XRAY_PORT= 'ENTRY_LOCAL_NETS="172.17.0.0/16 172.29.172.0/24"'
    run_script multihop-entry-net up
    [ "$status" -eq 0 ]
    diff "$IPT_DIR/filter.MULTIHOP-FWD" <(expected_fwd)
    ! grep -q -e conntrack "$IPT_DIR/filter.MULTIHOP-FWD" "$IPT_DIR/mangle.MULTIHOP-MARK" || false
    no_violations
  done
}

@test "no rule anywhere matches --sport 443" {
  for env in reality_env awg_xray_env; do
    "$env"; guard_on
    run_script multihop-entry-net up
    [ "$status" -eq 0 ]
    grep -q -e 'ctorigdstport 443' "$IPT_DIR/mangle.MULTIHOP-MARK"
    ! grep -rqE -e '--sport 443( |$)' "$IPT_DIR" || false
    ! grep -q -e 'sport 443' "$STUB_LOG" || false
    no_violations
  done
}

@test "reality without ENTRY_LOCAL_NETS fails before changing anything" {
  env_with UPLINK_TRANSPORT=reality ENTRY_XRAY_PORT=443
  run_script multihop-entry-net up
  [ "$status" -ne 0 ]
  grep -qF "ENTRY_LOCAL_NETS" <<<"$output"
  ! grep -q -e '^iptables\|^ip \|^ipset' "$STUB_LOG" || false
}

@test "unknown transport fails before changing anything" {
  env_with UPLINK_TRANSPORT=wireguard 'ENTRY_LOCAL_NETS="172.17.0.0/16"'
  run_script multihop-entry-net up
  [ "$status" -ne 0 ]
  grep -qF "UPLINK_TRANSPORT" <<<"$output"
  ! grep -q -e '^iptables\|^ip \|^ipset' "$STUB_LOG" || false
}

@test "down in reality mode removes the local route and MULTIHOP-TPROXY" {
  reality_env
  run_script multihop-entry-net up
  [ "$status" -eq 0 ]
  run_script multihop-entry-net down
  [ "$status" -eq 0 ]
  [ ! -s "$IP_DIR/routes" ]
  [ ! -s "$IPT_DIR/mangle.PREROUTING" ]
  ! ls "$IPT_DIR" | grep -e MULTIHOP || false
}
