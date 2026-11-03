"""entry_xray seeds the app's Xray state once and restores it from a staged directory."""
import json
import os
import subprocess

import pytest
import yaml

from test_render import FIXTURE_VAULT_PASS, RENDER_DIR, ROOT

SERVER_JSON = ROOT / "tests" / "fixtures" / "amnezia-xray-server.json"

SEED_PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - {fixture}
  roles:
    - entry_xray
"""

RESTORE_PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  vars_files:
    - {fixture}
  tasks:
    - ansible.builtin.include_role:
        name: entry_xray
        tasks_from: restore
"""


def _env():
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    return env


def _play(tmp_path, name, text, *args):
    playbook = tmp_path / f"{name}.yml"
    playbook.write_text(text.format(fixture=RENDER_DIR / "fixture_vars.yml"))
    return subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", "ansible_connection=local",
         *args, str(playbook)],
        cwd=ROOT, env=_env(), capture_output=True, text=True,
    )


def _seed(tmp_path, state):
    proc = _play(tmp_path, "seed", SEED_PLAYBOOK, "-e", f"entry_xray_state_dir={state}",
                 "--tags", "entry_xray_seed")
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return proc.stdout


def test_seed_writes_the_app_layout_once(tmp_path):
    fx = yaml.safe_load((RENDER_DIR / "fixture_vars.yml").read_text())["vault_entry_xray"]
    state = tmp_path / "state"

    _seed(tmp_path, state)
    # configure_container.sh writes each key with printf '%s\n'.
    assert {p.name: p.read_text() for p in state.iterdir() if p.suffix == ".key"} == {
        "xray_uuid.key": fx["uuid"] + "\n",
        "xray_private.key": fx["private_key"] + "\n",
        "xray_public.key": fx["public_key"] + "\n",
        "xray_short_id.key": fx["short_id"] + "\n",
    }
    assert (state / "server.json").read_text() == SERVER_JSON.read_text()
    for p in state.iterdir():
        assert oct(p.stat().st_mode & 0o777) == "0o600", p.name
    assert oct(state.stat().st_mode & 0o777) == "0o700"

    # The app adds a user: a second client in server.json and a clientsTable.
    cfg = json.loads((state / "server.json").read_text())
    cfg["inbounds"][0]["settings"]["clients"].append(
        {"id": "33333333-3333-4333-8333-333333333333", "flow": "xtls-rprx-vision"})
    (state / "server.json").write_text(json.dumps(cfg, indent=4, sort_keys=True) + "\n")
    (state / "clientsTable").write_text('[{"clientId":"33333333-3333-4333-8333-333333333333"}]\n')
    snapshot = {p.name: p.read_bytes() for p in state.iterdir()}

    out = _seed(tmp_path, state)
    assert {p.name: p.read_bytes() for p in state.iterdir()} == snapshot
    assert "changed=0" in out


def test_seed_keeps_keys_the_app_generated(tmp_path):
    # server.json present: nothing is seeded, even if a key file is missing.
    state = tmp_path / "state"
    state.mkdir()
    (state / "server.json").write_text("{}\n")
    _seed(tmp_path, state)
    assert [p.name for p in state.iterdir()] == ["server.json"]


def _restore(tmp_path, staged, state):
    return _play(tmp_path, "restore", RESTORE_PLAYBOOK,
                 "-e", f"entry_xray_state_dir={state}",
                 "-e", f"entry_xray_restore_dir={staged}",
                 "-e", "entry_xray_manage_container=false")


def _staged(tmp_path, files):
    staged = tmp_path / "xray"
    staged.mkdir()
    for name, data in files.items():
        (staged / name).write_text(data)
    return staged


GOOD = {"server.json": "restored\n", "xray_uuid.key": "u\n", "xray_private.key": "p\n",
        "xray_public.key": "k\n", "xray_short_id.key": "s\n", "clientsTable": "[]\n"}


def test_restore_replaces_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "server.json").write_text("old\n")
    (state / "stale").write_text("x")
    proc = _restore(tmp_path, _staged(tmp_path, GOOD), state)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert {p.name: p.read_text() for p in state.iterdir()} == GOOD
    for p in state.iterdir():
        assert oct(p.stat().st_mode & 0o777) == "0o600", p.name
    assert not (tmp_path / "state.restore-staging").exists()


def test_restore_rejects_incomplete_dir_and_keeps_state(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "server.json").write_text("live\n")
    files = {k: v for k, v in GOOD.items() if k != "xray_private.key"}
    proc = _restore(tmp_path, _staged(tmp_path, files), state)
    assert proc.returncode != 0
    assert "xray_private.key" in proc.stdout + proc.stderr
    assert [p.name for p in state.iterdir()] == ["server.json"]
    assert (state / "server.json").read_text() == "live\n"


def _port_check(tmp_path, state, *args):
    return _play(tmp_path, "portcheck", SEED_PLAYBOOK, "-e", f"entry_xray_state_dir={state}",
                 "--tags", "entry_xray_port_check", *args)


def test_port_check_passes_without_or_with_a_matching_server_json(tmp_path):
    state = tmp_path / "state"
    proc = _port_check(tmp_path, state)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    state.mkdir()
    (state / "server.json").write_text(SERVER_JSON.read_text())
    proc = _port_check(tmp_path, state)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "changed=0" in proc.stdout


@pytest.mark.parametrize("text, found", [
    (SERVER_JSON.read_text().replace('"port": 443', '"port": 8443'), "8443"),
    ("{}\n", "no readable inbounds[0].port"),
])
def test_port_check_refuses_another_port(tmp_path, text, found):
    # The published port, firewall and issued keys are built from entry_xray_port;
    # the app's server.json keeps the first deploy's port.
    state = tmp_path / "state"
    state.mkdir()
    (state / "server.json").write_text(text)
    proc = _port_check(tmp_path, state)
    out = proc.stdout + proc.stderr
    assert proc.returncode != 0
    assert found in out and "entry_xray_port is 443" in out
    assert "cannot change after the first deploy" in out and "restore.yml" in out
    assert "privateKey" not in out
    assert (state / "server.json").read_text() == text


def test_port_check_is_skipped_during_a_restore(tmp_path):
    state = tmp_path / "state"
    state.mkdir()
    (state / "server.json").write_text("{}\n")
    proc = _port_check(tmp_path, state, "-e", f"entry_xray_restore_dir={tmp_path}")
    assert proc.returncode == 0, proc.stdout + proc.stderr
