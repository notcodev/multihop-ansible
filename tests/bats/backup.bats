load helpers

# docker/aws/age are stubs. docker inspect prints $MOUNTS/<container> (one
# "Type Source Destination" line per mount) or fails if it is missing. aws
# saves each uploaded stdin under $UPLOADS/<last path component>; age marks its
# output so tests can tell plaintext from ciphertext. tar is the real one: GNU
# tar runs the script's flags as-is, bsdtar (macOS) goes through a wrapper
# selected by MULTIHOP_TAR.
setup() {
  export MULTIHOP_ENV="$BATS_TEST_TMPDIR/multihop.env"
  export MULTIHOP_STATE_DIR="$BATS_TEST_TMPDIR/state"
  export STUB_LOG="$BATS_TEST_TMPDIR/stub.log"
  export UPLOADS="$BATS_TEST_TMPDIR/uploads"
  export ENTRY_DIR="$BATS_TEST_TMPDIR/entry-awg"
  export XRAY_DIR="$BATS_TEST_TMPDIR/entry-xray"
  export MOUNTS="$BATS_TEST_TMPDIR/mounts"
  mkdir -p "$BATS_TEST_TMPDIR/bin" "$UPLOADS" "$ENTRY_DIR" "$MULTIHOP_STATE_DIR" "$MOUNTS"
  : > "$STUB_LOG"
  cat > "$MULTIHOP_ENV" <<ENV
ENTRY_STATE_DIR=$ENTRY_DIR
S3_ENDPOINT=https://s3.example.com
S3_REGION=eu-1
BUCKET=bkt
PREFIX=multihop
AGE_RECIPIENT=age1recipient
ENV
  echo "[Interface]" > "$ENTRY_DIR/awg0.conf"
  echo "key" > "$ENTRY_DIR/wireguard_server_private_key.key"

  echo "bind $ENTRY_DIR /opt/amnezia/awg" > "$MOUNTS/amnezia-awg2"
  cat > "$BATS_TEST_TMPDIR/bin/docker" <<'STUB'
#!/bin/sh
echo "docker $*" >> "$STUB_LOG"
for a in "$@"; do last="$a"; done
[ -f "$MOUNTS/$last" ] || { echo "Error: No such object: $last" >&2; exit 1; }
cat "$MOUNTS/$last"
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/docker"
  cat > "$BATS_TEST_TMPDIR/bin/age" <<'STUB'
#!/bin/sh
echo "age $*" >> "$STUB_LOG"
echo "AGE-ENCRYPTED"
cat
STUB
  cat > "$BATS_TEST_TMPDIR/bin/aws" <<'STUB'
#!/bin/sh
echo "aws $*" >> "$STUB_LOG"
[ -n "$AWS_FAIL" ] && { cat > /dev/null; exit 1; }
for a in "$@"; do last="$a"; done
cat > "$UPLOADS/$(basename "$last")"
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/age" "$BATS_TEST_TMPDIR/bin/aws"

  if ! tar --version 2>/dev/null | grep -q GNU; then
    cat > "$BATS_TEST_TMPDIR/bin/tar-compat" <<'STUB'
#!/bin/sh
# bsdtar stand-in for the GNU flags in multihop-backup.
args=""
for a in "$@"; do
  case "$a" in
    --sort=name|--mtime=@0|--owner=0|--group=0) ;;
    *) args="$args $a" ;;
  esac
done
# shellcheck disable=SC2086
exec tar --uid 0 --gid 0 $args
STUB
    chmod +x "$BATS_TEST_TMPDIR/bin/tar-compat"
    export MULTIHOP_TAR="$BATS_TEST_TMPDIR/bin/tar-compat"
  fi
}

uploaded_objects() { ls "$UPLOADS" | grep '^entry-.*\.tar\.age$' || true; }

@test "awg drift writes DRIFT, still uploads host state, exits 2" {
  # The app's reinstall: a named volume instead of the bind mount.
  echo "volume /var/lib/docker/volumes/amnezia-awg-data/_data /opt/amnezia/awg-data" > "$MOUNTS/amnezia-awg2"
  run_script multihop-backup
  [ "$status" -eq 2 ]
  [[ "$output" == *'ERROR: amnezia-awg2 lost its bind mount (app reinstall?) — see README "Recovery"'* ]]
  grep -q ' amnezia-awg2$' "$MULTIHOP_STATE_DIR/backup/DRIFT"
  [ "$(wc -l < "$MULTIHOP_STATE_DIR/backup/DRIFT")" -eq 1 ]
  obj="$(uploaded_objects)"
  [ -n "$obj" ]
  tail -n +2 "$UPLOADS/$obj" | tar -tf - | grep -qx './awg0.conf'

  # Unchanged host state: nothing to upload, still drift.
  rm -f "$UPLOADS"/*
  run_script multihop-backup
  [ "$status" -eq 2 ]
  [ -z "$(uploaded_objects)" ]

  # Mount back: DRIFT is cleared.
  echo "bind $ENTRY_DIR /opt/amnezia/awg" > "$MOUNTS/amnezia-awg2"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  [ ! -e "$MULTIHOP_STATE_DIR/backup/DRIFT" ]
}

@test "missing container is drift" {
  rm -f "$MOUNTS/amnezia-awg2"
  run_script multihop-backup
  [ "$status" -eq 2 ]
  grep -q ' amnezia-awg2$' "$MULTIHOP_STATE_DIR/backup/DRIFT"
}

@test "unchanged state does not upload" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  : > "$STUB_LOG"
  rm -f "$UPLOADS"/*
  run_script multihop-backup
  [ "$status" -eq 0 ]
  ! grep -q '^aws ' "$STUB_LOG" || false
  [ -z "$(ls "$UPLOADS")" ]
}

@test "changed state uploads encrypted object and latest pointer" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  grep -q '^age -r age1recipient' "$STUB_LOG"
  grep -q -- '^aws --profile multihop-backup --endpoint-url https://s3.example.com s3 cp - s3://bkt/multihop/entry-' "$STUB_LOG"
  grep -q -- 's3://bkt/multihop/latest' "$STUB_LOG"
  obj="$(uploaded_objects)"
  [[ "$obj" =~ ^entry-[0-9]{8}T[0-9]{6}Z-[0-9a-f]{12}\.tar\.age$ ]]
  head -n1 "$UPLOADS/$obj" | grep -qx AGE-ENCRYPTED
  [ "$(cat "$UPLOADS/latest")" = "multihop/$obj" ]
  [ -s "$MULTIHOP_STATE_DIR/backup/last.sha256" ]
  [[ "$obj" == *"$(head -c12 "$MULTIHOP_STATE_DIR/backup/last.sha256").tar.age" ]]

  # A change uploads again.
  echo extra > "$ENTRY_DIR/clientsTable"
  : > "$STUB_LOG"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  grep -q '^aws .*s3 cp - s3://bkt/multihop/entry-' "$STUB_LOG"
}

@test "archive has state files at the archive root" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  obj="$(uploaded_objects)"
  tail -n +2 "$UPLOADS/$obj" | tar -tf - | grep -qx './awg0.conf'
}

@test "--force uploads even if unchanged" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  : > "$STUB_LOG"
  run_script multihop-backup --force
  [ "$status" -eq 0 ]
  grep -q '^aws .*s3 cp - s3://bkt/multihop/entry-' "$STUB_LOG"
}

@test "upload failure exits 1 and does not update last.sha256" {
  export AWS_FAIL=1
  run_script multihop-backup
  [ "$status" -eq 1 ]
  [ ! -e "$MULTIHOP_STATE_DIR/backup/last.sha256" ]
}

@test "archive is deterministic" {
  run_script multihop-backup
  [ "$status" -eq 0 ]
  first="$(cat "$MULTIHOP_STATE_DIR/backup/last.sha256")"
  rm -f "$MULTIHOP_STATE_DIR/backup/last.sha256"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  [ "$first" = "$(cat "$MULTIHOP_STATE_DIR/backup/last.sha256")" ]
}

# --- the entry Xray state --------------------------------------------------------

with_xray() {
  mkdir -p "$XRAY_DIR"
  echo "ENTRY_XRAY_STATE_DIR=$XRAY_DIR" >> "$MULTIHOP_ENV"
  echo "bind $XRAY_DIR /opt/amnezia/xray" > "$MOUNTS/amnezia-xray"
  echo '{"inbounds": []}' > "$XRAY_DIR/server.json"
  for k in uuid private public short_id; do echo "v-$k" > "$XRAY_DIR/xray_$k.key"; done
}

archive_members() { tail -n +2 "$UPLOADS/$(uploaded_objects)" | tar -tf - | sed 's,/$,,' | sort; }

@test "no xray subdir without ENTRY_XRAY_STATE_DIR" {
  echo "ENTRY_XRAY_STATE_DIR=" >> "$MULTIHOP_ENV"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  ! archive_members | grep -q xray || false
  ! grep -q 'inspect.*amnezia-xray' "$STUB_LOG" || false
}

@test "archive contains xray subdir when ENTRY_XRAY_STATE_DIR is set" {
  with_xray
  echo '[]' > "$XRAY_DIR/clientsTable"
  echo junk > "$XRAY_DIR/server.json.bak"
  mkdir "$XRAY_DIR/sub" && echo x > "$XRAY_DIR/sub/f"
  ln -s /etc/passwd "$XRAY_DIR/xray_link"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  [ "$(archive_members)" = "$(printf '%s\n' . ./awg0.conf ./wireguard_server_private_key.key ./xray \
    ./xray/clientsTable ./xray/server.json ./xray/xray_private.key ./xray/xray_public.key \
    ./xray/xray_short_id.key ./xray/xray_uuid.key | sort)" ]
  [ "$(tail -n +2 "$UPLOADS/$(uploaded_objects)" | tar -xOf - ./xray/xray_uuid.key)" = "v-uuid" ]
}

@test "xray state without server.json is not archived" {
  with_xray
  rm "$XRAY_DIR/server.json"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  ! archive_members | grep -q xray || false
}

@test "xray drift writes DRIFT, still uploads, exits 2" {
  with_xray
  # The app's reinstall mounts its named volume at the same destination.
  echo "volume /var/lib/docker/volumes/amnezia-xray-data/_data /opt/amnezia/xray" > "$MOUNTS/amnezia-xray"
  run_script multihop-backup
  [ "$status" -eq 2 ]
  [[ "$output" == *'ERROR: amnezia-xray lost its bind mount'* ]]
  [ "$(cat "$MULTIHOP_STATE_DIR/backup/DRIFT" | wc -l)" -eq 1 ]
  grep -q ' amnezia-xray$' "$MULTIHOP_STATE_DIR/backup/DRIFT"
  archive_members | grep -qx './xray/server.json'
  archive_members | grep -qx './awg0.conf'
  [ -s "$MULTIHOP_STATE_DIR/backup/last.sha256" ]
}

@test "xray bind mount of another directory is drift" {
  with_xray
  echo "bind /srv/elsewhere /opt/amnezia/xray" > "$MOUNTS/amnezia-xray"
  run_script multihop-backup
  [ "$status" -eq 2 ]
  grep -q ' amnezia-xray$' "$MULTIHOP_STATE_DIR/backup/DRIFT"
}

@test "drift on both containers writes one line each" {
  with_xray
  rm -f "$MOUNTS/amnezia-awg2" "$MOUNTS/amnezia-xray"
  run_script multihop-backup
  [ "$status" -eq 2 ]
  [ "$(wc -l < "$MULTIHOP_STATE_DIR/backup/DRIFT")" -eq 2 ]
  grep -q ' amnezia-awg2$' "$MULTIHOP_STATE_DIR/backup/DRIFT"
  grep -q ' amnezia-xray$' "$MULTIHOP_STATE_DIR/backup/DRIFT"
  [ -n "$(uploaded_objects)" ]
}

@test "hash unchanged when neither state changed" {
  with_xray
  run_script multihop-backup
  [ "$status" -eq 0 ]
  first="$(cat "$MULTIHOP_STATE_DIR/backup/last.sha256")"
  rm -f "$UPLOADS"/*
  run_script multihop-backup
  [ "$status" -eq 0 ]
  [[ "$output" == *"state unchanged"* ]]
  [ -z "$(uploaded_objects)" ]
  [ "$first" = "$(cat "$MULTIHOP_STATE_DIR/backup/last.sha256")" ]

  # A file outside the six names is not state.
  echo junk > "$XRAY_DIR/notes.txt"
  run_script multihop-backup
  [[ "$output" == *"state unchanged"* ]]

  # An Xray change alone uploads.
  echo '[]' > "$XRAY_DIR/clientsTable"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  [ -n "$(uploaded_objects)" ]
  [ "$first" != "$(cat "$MULTIHOP_STATE_DIR/backup/last.sha256")" ]
}

@test "archive without xray matches the pre-xray layout byte for byte" {
  # Same bytes as the old `tar -C ENTRY_STATE_DIR .`: no spurious upload after the upgrade.
  run_script multihop-backup
  [ "$status" -eq 0 ]
  tar_cmd="${MULTIHOP_TAR:-tar}"
  expected="$($tar_cmd --sort=name --mtime=@0 --owner=0 --group=0 --numeric-owner -C "$ENTRY_DIR" -cf - . | shasum -a 256 | cut -d' ' -f1)"
  [ "$expected" = "$(cat "$MULTIHOP_STATE_DIR/backup/last.sha256")" ]
}

@test "an xray entry in the AWG dir is refused, with or without Xray" {
  # It would land at ./xray/ and make every backup unrestorable.
  mkdir "$ENTRY_DIR/xray"
  run_script multihop-backup
  [ "$status" -eq 1 ]
  [[ "$output" == *"$ENTRY_DIR/xray exists"* ]]
  [ -z "$(uploaded_objects)" ]

  with_xray
  run_script multihop-backup
  [ "$status" -eq 1 ]
  [ -z "$(uploaded_objects)" ]

  rmdir "$ENTRY_DIR/xray"
  ln -s /tmp "$ENTRY_DIR/xray"
  run_script multihop-backup
  [ "$status" -eq 1 ]
}

@test "a symlink swapped in before the copy is not followed" {
  with_xray
  echo "TOP-SECRET" > "$BATS_TEST_TMPDIR/secret"
  real_cp="$(command -v cp)"
  # The race: xray_private.key becomes a symlink between the test and the copy.
  cat > "$BATS_TEST_TMPDIR/bin/cp" <<STUB
#!/bin/sh
case "\$*" in *"$XRAY_DIR/xray_private.key"*)
  rm -f "$XRAY_DIR/xray_private.key"; ln -s "$BATS_TEST_TMPDIR/secret" "$XRAY_DIR/xray_private.key" ;;
esac
exec "$real_cp" "\$@"
STUB
  chmod +x "$BATS_TEST_TMPDIR/bin/cp"
  run_script multihop-backup
  [ "$status" -eq 0 ]
  [[ "$output" == *"xray_private.key is not a regular file, left out"* ]]
  ! archive_members | grep -q xray_private.key || false
  ! tail -n +2 "$UPLOADS/$(uploaded_objects)" | grep -aq TOP-SECRET || false
}
