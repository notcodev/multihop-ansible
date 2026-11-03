load helpers

# tests/integration/run.sh must refuse every mode but help when a lab IP is a
# host of the prod inventory. Everything here is temp files: LAB_STATE and
# PROD_HOSTS point away from the real .state and inventories/prod, and ssh, uv,
# ansible-playbook & co are stubs that log, so a broken guard shows up in
# $STUB_LOG instead of reaching a host.
setup() {
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  export LAB_STATE="$BATS_TEST_TMPDIR/state"
  export PROD_HOSTS="$BATS_TEST_TMPDIR/prod-hosts.yml"
  mkdir -p "$LAB_STATE"
  : > "$STUB_LOG"
  local c
  for c in ssh scp uv ansible-playbook ansible age-keygen openssl aws; do stub "$c" "" 1; done
  cat > "$PROD_HOSTS" <<'YML'
---
all:
  hosts:
    prod-entry:
      ansible_host: 198.51.100.10
    prod-exit: {ansible_host: "198.51.100.20", ansible_port: 22}
    203.0.113.99:
  children:
    entry: {hosts: {prod-entry: {}}}
YML
  cat > "$LAB_STATE/lab.env" <<'ENV'
ENTRY_IP=192.0.2.10
EXIT_IP=192.0.2.20
EXIT2_IP=192.0.2.30
ENV
}

runsh() { # runsh <args...>: run.sh without lab IPs leaking in from the caller's env
  PATH="$BATS_TEST_TMPDIR/bin:$PATH" run env -u ENTRY_IP -u EXIT_IP -u EXIT2_IP \
    -u CLIENT_IP -u ENTRY2_IP -u LAB_CLIENT_IP "$@" "$REPO_ROOT/tests/integration/run.sh" "${RUNSH_ARGS[@]}"
}

@test "lab guard: no overlap passes" {
  RUNSH_ARGS=(guard); runsh
  [ "$status" -eq 0 ]
  [[ "$output" == *"no lab IP is a prod ansible_host"* ]] || false
}

@test "lab guard: a block-style prod ansible_host as ENTRY_IP refuses every mode" {
  echo "ENTRY_IP=198.51.100.10" >> "$LAB_STATE/lab.env"
  local m
  for m in init deploy client check swap "swap-entry reachable" clean guard; do
    read -ra RUNSH_ARGS <<< "$m"; runsh
    echo "mode $m: status $status: $output"
    [ "$status" -eq 1 ]
    [[ "$output" == *"ENTRY_IP=198.51.100.10"* ]] || false
    [[ "$output" == *"$PROD_HOSTS"* ]] || false
  done
  [ ! -s "$STUB_LOG" ]
}

@test "lab guard: a quoted flow-style prod ansible_host as EXIT2_IP refuses" {
  echo "EXIT2_IP=198.51.100.20" >> "$LAB_STATE/lab.env"
  RUNSH_ARGS=(check); runsh
  [ "$status" -eq 1 ]
  [[ "$output" == *"EXIT2_IP=198.51.100.20"* ]] || false
  [ ! -s "$STUB_LOG" ]
}

@test "lab guard: CLIENT_IP, ENTRY2_IP and LAB_CLIENT_IP from the environment are checked" {
  local v
  for v in CLIENT_IP ENTRY2_IP LAB_CLIENT_IP; do
    RUNSH_ARGS=(swap); runsh "$v=198.51.100.10"
    echo "$v: status $status: $output"
    [ "$status" -eq 1 ]
    [[ "$output" == *"$v=198.51.100.10"* ]] || false
  done
  [ ! -s "$STUB_LOG" ]
}

@test "lab guard: CLIENT_IP defaulting to a prod EXIT2_IP names both" {
  echo "EXIT2_IP=198.51.100.20" >> "$LAB_STATE/lab.env"
  RUNSH_ARGS=(deploy); runsh
  [ "$status" -eq 1 ]
  [[ "$output" == *"EXIT2_IP=198.51.100.20"* ]] || false
  [[ "$output" == *"CLIENT_IP=198.51.100.20"* ]] || false
}

@test "lab guard: an inventory host name that is an IP counts" {
  echo "EXIT_IP=203.0.113.99" >> "$LAB_STATE/lab.env"
  RUNSH_ARGS=(check); runsh
  [ "$status" -eq 1 ]
  [[ "$output" == *"EXIT_IP=203.0.113.99"* ]] || false
}

@test "lab guard: a longer IP sharing a prefix is not a match" {
  echo "ENTRY_IP=198.51.100.1" >> "$LAB_STATE/lab.env"
  echo "EXIT_IP=98.51.100.20" >> "$LAB_STATE/lab.env"
  RUNSH_ARGS=(guard); runsh
  [ "$status" -eq 0 ]
}

@test "lab guard: no prod inventory passes" {
  rm "$PROD_HOSTS"
  RUNSH_ARGS=(guard); runsh
  [ "$status" -eq 0 ]
}

@test "lab guard: a vault-encrypted prod inventory is refused" {
  printf '$ANSIBLE_VAULT;1.1;AES256\n6162\n' > "$PROD_HOSTS"
  RUNSH_ARGS=(guard); runsh
  [ "$status" -eq 1 ]
  [[ "$output" == *"vault-encrypted"* ]] || false
}

@test "lab guard: help still prints without the guard" {
  echo "ENTRY_IP=198.51.100.10" >> "$LAB_STATE/lab.env"
  RUNSH_ARGS=(); runsh
  [ "$status" -eq 2 ]
  [[ "$output" == *"run.sh guard"* ]] || false
  [[ "$output" != *"refusing"* ]] || false
}
