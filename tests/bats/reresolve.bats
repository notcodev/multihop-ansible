load helpers

PUB="4oJHxVTJT48b2TYy1bZOQf/r1oSJDNpV+WUgAtiAj30="

setup() {
  export MULTIHOP_ENV="$BATS_TEST_TMPDIR/multihop.env"
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  cat > "$MULTIHOP_ENV" <<ENV
EXIT_DOMAIN=exit.example.com
EXIT_PORT=27887
EXIT_PUBKEY=$PUB
PUBLIC_IFACE=eth9
ENV
  # awg show <iface> endpoints: "<pubkey> <ip:port>" per peer
  stub docker "$PUB 198.51.100.7:27887"
  stub ip
  : > "$STUB_LOG"
}

# getent_answer <exit-code>: fake getent printing stdin as its answer.
getent_answer() {
  cat > "$BATS_TEST_TMPDIR/getent.out"
  printf '#!/bin/sh\necho "getent $*" >> "$STUB_LOG"\ncat "%s"\nexit %s\n' \
    "$BATS_TEST_TMPDIR/getent.out" "${1:-0}" > "$BATS_TEST_TMPDIR/bin/getent"
  chmod +x "$BATS_TEST_TMPDIR/bin/getent"
}

@test "updates endpoint when DNS changed" {
  getent_answer <<'A'
203.0.113.9     STREAM exit.example.com
203.0.113.9     DGRAM
203.0.113.9     RAW
203.0.113.10    STREAM
A
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  grep -qx -e 'getent ahostsv4 exit.example.com' "$STUB_LOG"
  grep -qx -e 'docker exec multihop-uplink awg show awg-uplink endpoints' "$STUB_LOG"
  grep -qxF -e "docker exec multihop-uplink awg set awg-uplink peer $PUB endpoint 203.0.113.9:27887" "$STUB_LOG"
}

@test "no-op when same" {
  stub getent "198.51.100.7    STREAM exit.example.com"
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  grep -q -e 'awg show' "$STUB_LOG"
  ! grep -q -e 'awg set' "$STUB_LOG" || false
}

@test "port change alone updates endpoint" {
  sed -i.bak 's/^EXIT_PORT=.*/EXIT_PORT=443/' "$MULTIHOP_ENV"
  stub getent "198.51.100.7    STREAM exit.example.com"
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  grep -qxF -e "docker exec multihop-uplink awg set awg-uplink peer $PUB endpoint 198.51.100.7:443" "$STUB_LOG"
}

@test "empty resolution keeps endpoint" {
  stub getent "" 0
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  ! grep -q -e 'awg set' "$STUB_LOG" || false
}

@test "getent failure keeps endpoint" {
  stub getent "" 2
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  ! grep -q -e 'awg set' "$STUB_LOG" || false
}

@test "non-address answer keeps endpoint" {
  stub getent "<html>     STREAM exit.example.com"
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  ! grep -q -e 'awg set' "$STUB_LOG" || false
}

@test "exit peer missing on the interface fails without awg set" {
  stub getent "203.0.113.9     STREAM exit.example.com"
  stub docker "f8mW4F2meajkmhRZIr+FocB3Y+fbvFgIRJsjNKBz/R4= 198.51.100.7:27887"
  run_script multihop-reresolve
  [ "$status" -ne 0 ]
  grep -q -e 'awg show' "$STUB_LOG"
  ! grep -q -e 'awg set' "$STUB_LOG" || false
}

@test "uplink container down fails without awg set" {
  stub getent "203.0.113.9     STREAM exit.example.com"
  stub docker "" 1
  run_script multihop-reresolve
  [ "$status" -ne 0 ]
  ! grep -q -e 'awg set' "$STUB_LOG" || false
}

# The public interface's group (rule 10120 in multihop-entry-net) is lost when
# the NIC is renamed or re-created; every run puts it back, whatever DNS says.
@test "re-asserts the public interface group even when DNS fails" {
  getent_answer 2 < /dev/null
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  grep -qx -e 'ip link set dev eth9 group 51820' "$STUB_LOG"
}

@test "a failing group re-assert does not stop the re-resolve" {
  stub ip "" 1
  getent_answer <<'A'
203.0.113.9     STREAM exit.example.com
A
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  grep -qF "cannot set the group of eth9" <<<"$output"
  grep -qxF -e "docker exec multihop-uplink awg set awg-uplink peer $PUB endpoint 203.0.113.9:27887" "$STUB_LOG"
}

# --- reality mode: the uplink is the entry's Xray container ---------------

reality_setup() {
  export STATE="$BATS_TEST_TMPDIR/state"
  mkdir -p "$STATE"
  cat >> "$MULTIHOP_ENV" <<ENV
UPLINK_TRANSPORT=reality
UPLINK_STATE_DIR=$STATE
ENV
}

@test "reality mode restarts uplink xray when the exit IP changes" {
  reality_setup
  echo 203.0.113.8 > "$STATE/exit-ip"
  stub getent "203.0.113.9     STREAM exit.example.com"
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  grep -qxF -e 'docker restart multihop-uplink-xray' "$STUB_LOG"
  ! grep -q -e 'awg' "$STUB_LOG" || false
  [ "$(cat "$STATE/exit-ip")" = "203.0.113.9" ]
}

@test "reality mode first run records the IP without a restart" {
  reality_setup
  stub getent "203.0.113.9     STREAM exit.example.com"
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  [ "$(cat "$STATE/exit-ip")" = "203.0.113.9" ]
  ! grep -q -e '^docker' "$STUB_LOG" || false
}

@test "reality mode does nothing when the IP is unchanged" {
  reality_setup
  echo 203.0.113.9 > "$STATE/exit-ip"
  stub getent "203.0.113.9     STREAM exit.example.com"
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  ! grep -q -e '^docker' "$STUB_LOG" || false
  [ "$(cat "$STATE/exit-ip")" = "203.0.113.9" ]
}

@test "reality mode keeps everything on a failed resolve" {
  reality_setup
  echo 203.0.113.8 > "$STATE/exit-ip"
  stub getent "" 2
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
  ! grep -q -e '^docker' "$STUB_LOG" || false
  [ "$(cat "$STATE/exit-ip")" = "203.0.113.8" ]
}

@test "reality mode does not need the AWG keys" {
  reality_setup
  sed -i.bak '/^EXIT_PORT=/d;/^EXIT_PUBKEY=/d' "$MULTIHOP_ENV"
  stub getent "203.0.113.9     STREAM exit.example.com"
  run_script multihop-reresolve
  [ "$status" -eq 0 ]
}
