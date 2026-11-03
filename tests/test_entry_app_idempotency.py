"""The entry_app seed tasks must never overwrite state the app has changed."""
import os
import subprocess

from test_render import FIXTURE_VAULT_PASS, RENDER_DIR, ROOT

PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - {fixture}
  roles:
    - entry_app
"""


def _run(playbook, state_dir):
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    proc = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", "ansible_connection=local",
         "-e", f"entry_state_dir={state_dir}", "--tags", "entry_app_seed",
         str(playbook)],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def test_seed_tasks_keep_app_state(tmp_path):
    playbook = tmp_path / "play.yml"
    playbook.write_text(PLAYBOOK.format(fixture=RENDER_DIR / "fixture_vars.yml"))
    state = tmp_path / "state"

    _run(playbook, state)
    conf = (state / "awg0.conf").read_text()
    assert "[Peer]" not in conf
    assert (state / "wireguard_psk.key").read_text().endswith("\n")
    assert oct((state / "awg0.conf").stat().st_mode & 0o777) == "0o600"
    assert not (state / "clientsTable").exists()

    # The app adds a user: peer in awg0.conf and a clientsTable.
    with (state / "awg0.conf").open("a") as fh:
        fh.write("\n[Peer]\nPublicKey = FAKEPEERKEY=\nAllowedIPs = 10.8.1.2/32\n")
    (state / "clientsTable").write_text('[{"clientId":"FAKEPEERKEY="}]\n')
    snapshot = {p.name: p.read_bytes() for p in state.iterdir()}

    out = _run(playbook, state)
    assert {p.name: p.read_bytes() for p in state.iterdir()} == snapshot
    assert "changed=0" in out


RESTORE_PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - {fixture}
  tasks:
    - ansible.builtin.include_role:
        name: entry_app
        tasks_from: restore
"""


def _restore(tmp_path, archive, state):
    playbook = tmp_path / "restore.yml"
    playbook.write_text(RESTORE_PLAYBOOK.format(fixture=RENDER_DIR / "fixture_vars.yml"))
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", "ansible_connection=local",
         "-e", f"entry_state_dir={state}", "-e", f"entry_restore_archive={archive}",
         "-e", "entry_app_manage_container=false", str(playbook)],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )


def _make_tar(tmp_path, name, members):
    src = tmp_path / f"{name}-src"
    for rel, data in members.items():
        (src / rel).parent.mkdir(parents=True, exist_ok=True)
        (src / rel).write_text(data)
    archive = tmp_path / f"{name}.tar"
    subprocess.run(["tar", "-cf", str(archive), "-C", str(src), "."], check=True)
    return archive


def test_restore_replaces_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "awg0.conf").write_text("old\n")
    (state / "stale").write_text("x")
    archive = _make_tar(tmp_path, "good", {
        "awg0.conf": "restored\n", "wireguard_server_private_key.key": "K\n",
        "clientsTable": "[]\n"})
    proc = _restore(tmp_path, archive, state)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert sorted(p.name for p in state.iterdir()) == [
        "awg0.conf", "clientsTable", "wireguard_server_private_key.key"]
    assert (state / "awg0.conf").read_text() == "restored\n"
    assert not (tmp_path / "state.restore-staging").exists()


def test_restore_rejects_nested_archive_and_keeps_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "awg0.conf").write_text("live\n")
    (state / "clientsTable").write_text("users\n")
    archive = _make_tar(tmp_path, "nested", {
        "entry-awg/awg0.conf": "x\n", "entry-awg/wireguard_server_private_key.key": "K\n"})
    proc = _restore(tmp_path, archive, state)
    assert proc.returncode != 0
    assert "does not contain awg0.conf" in proc.stdout + proc.stderr
    assert (state / "awg0.conf").read_text() == "live\n"
    assert (state / "clientsTable").read_text() == "users\n"


def test_restore_leaves_the_xray_subdir_out_of_the_awg_state(tmp_path):
    # The Xray state rides in the same archive under xray/; entry_xray restores it.
    state = tmp_path / "state"
    state.mkdir()
    archive = _make_tar(tmp_path, "with-xray", {
        "awg0.conf": "restored\n", "wireguard_server_private_key.key": "K\n",
        "xray/server.json": "{}\n", "xray/xray_uuid.key": "u\n"})
    proc = _restore(tmp_path, archive, state)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert sorted(p.name for p in state.iterdir()) == [
        "awg0.conf", "wireguard_server_private_key.key"]
