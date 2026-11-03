"""Playbooks: syntax-check every entry point and exercise the uplink key rotation."""
import json
import os
import subprocess
import sys

import pytest
import yaml

from test_awg_filter import awg
from test_render import FIXTURE_VAULT_PASS, ROOT

PLAYBOOKS = [
    "site.yml", "exit.yml", "entry.yml", "backup.yml", "restore.yml",
    "swap-exit.yml", "swap-entry.yml", "verify.yml",
]
EXAMPLE_INVENTORY = ROOT / "inventories" / "example"
# Dummy plaintext vault, generated per test session (gitignored).
VAULT_INVENTORY = ROOT / "tests" / "fixtures" / "inventory-vault"


def _env(**extra):
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    env.update(extra)
    return env


@pytest.fixture(scope="session")
def dummy_vault():
    """Example inventory + an unencrypted vault from gen-secrets.py."""
    vault_dir = VAULT_INVENTORY / "group_vars" / "all"
    vault_dir.mkdir(parents=True, exist_ok=True)
    # A host-less inventory source whose group_vars/all overlays the example.
    (VAULT_INVENTORY / "hosts.yml").write_text("---\nall: {}\n")
    for name, mode in (("vault.yml", "all"), ("vault_uplink.yml", "uplink-key")):
        out = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen-secrets.py"), mode],
                             check=True, capture_output=True, text=True).stdout
        (vault_dir / name).write_text(out)
    return ["-i", str(EXAMPLE_INVENTORY), "-i", str(VAULT_INVENTORY)]


def test_dummy_vault_reaches_hosts(dummy_vault):
    proc = subprocess.run(["ansible-inventory", *dummy_vault, "--host", "entry1"],
                          cwd=ROOT, env=_env(), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    hostvars = json.loads(proc.stdout)
    assert {"entry_domain", "vault_entry_awg", "vault_link_awg",
            "vault_uplink_entry"} <= hostvars.keys()


@pytest.mark.parametrize("playbook", sorted(
    set(PLAYBOOKS) | {p.name for p in (ROOT / "playbooks").glob("*.yml")}))
def test_syntax_all(dummy_vault, playbook):
    path = ROOT / "playbooks" / playbook
    assert path.exists(), f"missing playbook {playbook}"
    proc = subprocess.run(["ansible-playbook", *dummy_vault, "--syntax-check", str(path)],
                          cwd=ROOT, env=_env(), capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert "WARNING" not in proc.stderr, proc.stderr


def test_verify_entry_task_file_exists():
    assert (ROOT / "playbooks" / "tasks" / "verify-entry.yml").exists()


ROTATE_PLAYBOOK = """---
- hosts: localhost
  connection: local
  gather_facts: false
  tasks:
    - ansible.builtin.include_tasks: {task}
      vars:
        uplink_vault_file: {target}
    - ansible.builtin.copy:
        content: "{{{{ vault_uplink_entry | to_json }}}}"
        dest: {out}
        mode: "0600"
"""


def _rotate(tmp_path, target, env):
    # gen-secrets.py is found relative to the playbook dir, as in playbooks/.
    (tmp_path / "playbooks").mkdir(exist_ok=True)
    if not (tmp_path / "scripts").exists():
        (tmp_path / "scripts").symlink_to(ROOT / "scripts")
    playbook = tmp_path / "playbooks" / "play.yml"
    out = tmp_path / "loaded.json"
    playbook.write_text(ROTATE_PLAYBOOK.format(
        task=ROOT / "playbooks" / "tasks" / "rotate-uplink-key.yml", target=target, out=out))
    # Run from elsewhere: the rotation must not depend on the working directory.
    env = dict(env)
    pass_file = env.get("ANSIBLE_VAULT_PASSWORD_FILE")
    if pass_file and not os.path.isabs(pass_file):
        env["ANSIBLE_VAULT_PASSWORD_FILE"] = str(ROOT / pass_file)
    env["PWD"] = str(tmp_path)
    proc = subprocess.run(["ansible-playbook", "-i", "localhost,", str(playbook)],
                          cwd=tmp_path, env=env, capture_output=True, text=True)
    return proc, out


def test_rotate_uplink_key_writes_encrypted_vault_and_loads_it(tmp_path):
    vault_dir = tmp_path / "inv" / "group_vars" / "all"
    vault_dir.mkdir(parents=True)
    target = vault_dir / "vault_uplink.yml"
    target.write_text("old\n")

    proc, out = _rotate(tmp_path, target, _env())
    assert proc.returncode == 0, proc.stdout + proc.stderr

    raw = target.read_text()
    assert raw.startswith("$ANSIBLE_VAULT;"), "vault_uplink.yml must be encrypted"
    assert oct(target.stat().st_mode & 0o777) == "0o600"
    assert [p.name for p in vault_dir.iterdir()] == ["vault_uplink.yml"]
    view = subprocess.run(["ansible-vault", "view", str(target)], cwd=ROOT, env=_env(),
                          capture_output=True, text=True, check=True).stdout
    key = yaml.safe_load(view)["vault_uplink_entry"]
    assert awg.pubkey(key["private_key"]) == key["public_key"]
    # include_vars made the new key visible to the rest of the play.
    assert json.loads(out.read_text()) == key


def test_rotate_uplink_key_keeps_old_file_when_encryption_fails(tmp_path):
    vault_dir = tmp_path / "inv" / "group_vars" / "all"
    vault_dir.mkdir(parents=True)
    target = vault_dir / "vault_uplink.yml"
    target.write_text("old\n")

    # Executable password file: works for ansible-playbook (first call), then
    # fails, so ansible-vault inside the task cannot encrypt.
    passfile = tmp_path / "pass.sh"
    passfile.write_text(f'#!/bin/sh\n[ -e "{tmp_path}/used" ] && exit 1\n'
                        f': > "{tmp_path}/used"\necho dummy\n')
    passfile.chmod(0o700)
    proc, _ = _rotate(tmp_path, target, _env(ANSIBLE_VAULT_PASSWORD_FILE=str(passfile)))
    assert proc.returncode != 0
    assert "fatal: [localhost]" in proc.stdout and "ansible-vault encrypt" in proc.stdout
    assert target.read_text() == "old\n"
    assert [p.name for p in vault_dir.iterdir()] == ["vault_uplink.yml"]


def test_rotate_uplink_key_needs_a_vault_password_file(tmp_path):
    vault_dir = tmp_path / "inv" / "group_vars" / "all"
    vault_dir.mkdir(parents=True)
    target = vault_dir / "vault_uplink.yml"
    target.write_text("old\n")

    # A config without vault_password_file, as with --ask-vault-pass users.
    cfg = tmp_path / "ansible.cfg"
    cfg.write_text("[defaults]\ninterpreter_python = auto_silent\n")
    env = _env(ANSIBLE_CONFIG=str(cfg))
    env.pop("ANSIBLE_VAULT_PASSWORD_FILE", None)
    proc, _ = _rotate(tmp_path, target, env)
    assert proc.returncode != 0
    assert "needs a vault" in proc.stdout and "password file" in proc.stdout, proc.stdout
    assert target.read_text() == "old\n"


FAKE_DOCKER = """#!/bin/bash
# docker exec <container> awg show <iface> <what>
case "$6" in
  endpoints) printf 'PUB=\\t%s:51821\\n' "$FAKE_EP" ;;
  latest-handshakes) printf 'PUB=\\t%s\\n' "$FAKE_HS" ;;
esac
"""


def _wait_handshake(tmp_path, **env):
    """Run one attempt of the wait-handshake.yml shell with a fake docker."""
    task = yaml.safe_load((ROOT / "playbooks/tasks/wait-handshake.yml").read_text())[0]
    bindir = tmp_path / "bin"
    bindir.mkdir(exist_ok=True)
    (bindir / "docker").write_text(FAKE_DOCKER)
    (bindir / "docker").chmod(0o755)
    full = {"PATH": f"{bindir}:{os.environ['PATH']}", "CONTAINER": "c", "IFACE": "i",
            "ENDPOINT": "", "SINCE": "", "KICK": "", "FAKE_EP": "1.2.3.4", "FAKE_HS": "0"}
    full.update({k: str(v) for k, v in env.items()})
    return subprocess.run(["bash", "-c", task["ansible.builtin.shell"]["cmd"]],
                          env=full, capture_output=True, text=True)


def test_wait_handshake_reports_age_and_never(tmp_path):
    now = int(subprocess.run(["date", "+%s"], capture_output=True, text=True).stdout)
    proc = _wait_handshake(tmp_path, FAKE_HS=now - 10)
    assert proc.returncode == 0 and 10 <= int(proc.stdout) < 20
    proc = _wait_handshake(tmp_path, FAKE_HS=0)
    assert proc.returncode == 0 and int(proc.stdout) > 10**9


def test_wait_handshake_endpoint_is_matched_exactly(tmp_path):
    now = int(subprocess.run(["date", "+%s"], capture_output=True, text=True).stdout)
    assert _wait_handshake(tmp_path, ENDPOINT="1.2.3.4", FAKE_EP="1.2.3.4",
                           FAKE_HS=now).returncode == 0
    for other in ("11.2.3.4", "1.2.3.40", "5.6.7.8"):
        proc = _wait_handshake(tmp_path, ENDPOINT="1.2.3.4", FAKE_EP=other, FAKE_HS=now)
        assert proc.returncode != 0, other


def test_wait_handshake_since_requires_a_newer_handshake(tmp_path):
    now = int(subprocess.run(["date", "+%s"], capture_output=True, text=True).stdout)
    assert _wait_handshake(tmp_path, SINCE=now, FAKE_HS=now - 5).returncode != 0
    assert _wait_handshake(tmp_path, SINCE=now, FAKE_HS=now).returncode == 0


def test_entry_uplink_applies_its_handlers_before_the_next_role():
    # Rule/script changes must be live before entry_app converges amnezia-awg2,
    # and a later failure (e.g. the app image build) must not drop the
    # pending reload: Ansible forgets notifications of a failed play.
    tasks = yaml.safe_load((ROOT / "roles" / "entry_uplink" / "tasks" / "main.yml").read_text())
    assert tasks[-1].get("ansible.builtin.meta") == "flush_handlers"
    container = next(i for i, t in enumerate(tasks)
                     if t.get("name") == "Run multihop-uplink container")
    assert container < len(tasks) - 1  # the restart handler finds the container


def _tasks_by_name(path):
    return {t.get("name"): t for t in yaml.safe_load((ROOT / path).read_text())}


def test_app_image_rebuilt_unless_it_carries_our_build_label():
    # An app reinstall rebuilds `amnezia-awg2` from upstream (no exclusion of the
    # AWG port in the UDP masquerade); a restore must not reuse that image.
    tasks = _tasks_by_name("roles/entry_app/tasks/main.yml")
    build = tasks["Build the app image"]["community.docker.docker_image"]
    assert build["build"]["labels"] == {"org.multihop.build": "{{ entry_app_build_id | trim }}"}
    assert "entry_app_image_build_label" in build["force_source"]
    assert "entry_app_build_id" in build["force_source"]
    decide = tasks["Decide whether the app image must be built"]["ansible.builtin.set_fact"]
    assert "stat.checksum" in decide["entry_app_build_id"]
    assert "org.multihop.build" in decide["entry_app_image_build_label"]


def test_verify_checks_the_app_container_is_ours():
    tasks = _tasks_by_name("playbooks/tasks/verify-entry.yml")
    that = tasks["Assert the app container is the one entry_app builds"]["ansible.builtin.assert"]["that"]
    assert "'awg=up' in verify_app.stdout_lines" in that
    assert "'to_ports=2' in verify_app.stdout_lines" in that
    assert any("label=[0-9a-f]{64}" in c for c in that)


def _unit(path):
    import configparser
    cp = configparser.ConfigParser(strict=False, interpolation=None)
    cp.optionxform = str
    cp.read_string((ROOT / path).read_text())
    return cp


def test_docker_cannot_start_without_the_entry_rules():
    # Wants= alone lets Docker (and amnezia-awg2) start when `up` failed at boot.
    unit = _unit("roles/entry_uplink/files/docker-multihop.conf")
    assert unit["Service"]["ExecStartPre"] == "/usr/local/sbin/multihop-entry-net up"
    assert "multihop-net.service" in unit["Unit"]["After"]


def test_exit_forwarding_comes_back_with_docker():
    # multihop-net (exit) is PartOf docker and stops with it; starting Docker
    # again must start it too, or the exit forwards nothing until a reboot.
    unit = _unit("roles/exit/files/docker-multihop.conf")
    assert "multihop-net.service" in unit["Unit"]["Wants"]
    tasks = _tasks_by_name("roles/exit/tasks/main.yml")
    dropin = tasks["Start multihop-net whenever Docker starts"]["ansible.builtin.copy"]
    assert dropin["dest"] == "/etc/systemd/system/docker.service.d/multihop.conf"


def test_common_sets_bbr():
    tasks = yaml.safe_load((ROOT / "roles/common/tasks/main.yml").read_text())
    items = []
    for t in tasks:
        if "ansible.posix.sysctl" in t:
            items += t["loop"]
    assert {"key": "net.core.default_qdisc", "value": "fq"} in items
    assert {"key": "net.ipv4.tcp_congestion_control", "value": "bbr"} in items
    persist = [t for t in tasks
               if t.get("ansible.builtin.copy", {}).get("dest") == "/etc/modules-load.d/multihop-bbr.conf"]
    assert persist and "tcp_bbr" in persist[0]["ansible.builtin.copy"]["content"]


def test_missing_reality_vault_message():
    base = ["ansible-playbook", "-i", "localhost,", "-e", "ansible_connection=local",
            str(ROOT / "tests" / "render" / "assert_vault.yml")]
    args = {"assert_vault_var": "vault_link_reality",
            "assert_vault_keys": ["private_key", "public_key", "short_id"],
            "assert_vault_hint": "uv run scripts/gen-secrets.py xray"}
    proc = subprocess.run([*base, "-e", json.dumps(args)], cwd=ROOT, env=_env(),
                          capture_output=True, text=True)
    assert proc.returncode != 0
    assert "gen-secrets.py xray" in proc.stdout + proc.stderr
    full = {**args, "vault_link_reality": {"private_key": "a", "public_key": "b",
                                           "short_id": "c"}}
    proc = subprocess.run([*base, "-e", json.dumps(full)], cwd=ROOT, env=_env(),
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stdout + proc.stderr


def test_entry_uplink_reloads_rules_unconditionally_before_containers():
    tasks = yaml.safe_load((ROOT / "roles/entry_uplink/tasks/main.yml").read_text())
    names = [t["name"] for t in tasks]
    reload_i = names.index("Apply the uplink mode rules to multihop-net")
    reload_task = tasks[reload_i]
    assert reload_task["ansible.builtin.systemd_service"] == {
        "name": "multihop-net", "state": "reloaded"}
    assert "when" not in reload_task
    assert reload_i < names.index("Run multihop-uplink container")
    assert reload_i < names.index("Run multihop-uplink-xray container")


def test_swap_entry_exit_push_applies_the_exit_plays_roles():
    exit_play = yaml.safe_load((ROOT / "playbooks/exit.yml").read_text())[0]
    swap = yaml.safe_load((ROOT / "playbooks/swap-entry.yml").read_text())
    push = next(p for p in swap if p.get("name") == "Push the new entry-uplink key to the exit")
    cond = "not _old_entry_reachable"
    assert len(push["roles"]) == len(exit_play["roles"])
    for got, want in zip(push["roles"], exit_play["roles"]):
        assert got["when"] == cond
        assert {k: v for k, v in got.items() if k != "when"} == want


def _plays(path):
    return yaml.safe_load((ROOT / path).read_text())


def _flat_tasks(plays):
    """(play index, task) for every task, descending into blocks."""
    def walk(tasks):
        for t in tasks or []:
            yield t
            for key in ("block", "rescue", "always"):
                yield from walk(t.get(key))
    for i, play in enumerate(plays):
        for t in walk(play.get("tasks")):
            yield i, t


def _dump(task):
    return yaml.safe_dump(task)


def test_swap_exit_flushes_entry_resolver():
    plays = _plays("playbooks/swap-exit.yml")
    dns = next(i for i, p in enumerate(plays) if p.get("name") == "Point the exit DNS record at the new exit")
    hits = [(i, t) for i, t in _flat_tasks(plays) if "resolvectl flush-caches" in _dump(t)]
    assert hits
    i, task = hits[0]
    assert i > dns
    assert plays[i]["hosts"] == "entry"
    assert task["failed_when"] is False and task["changed_when"] is False


def test_swap_exit_awg_stops_old_before_handshake_wait():
    plays = _plays("playbooks/swap-exit.yml")
    flat = list(_flat_tasks(plays))
    stop = next(n for n, (i, t) in enumerate(flat)
                if "community.docker.docker_container" in t
                and t["community.docker.docker_container"].get("name") == "multihop-exit"
                and plays[i]["hosts"] == "exit_old")
    wait = next(n for n, (i, t) in enumerate(flat) if "wait-handshake.yml" in _dump(t))
    assert stop < wait
    task = flat[stop][1]
    assert task["community.docker.docker_container"]["state"] == "stopped"
    assert "stop_old" in task["community.docker.docker_container"]["restart_policy"]
    assert "uplink_transport" in task["when"]


def test_swap_exit_reality_restarts_uplink_xray_and_waits_for_connection():
    plays = _plays("playbooks/swap-exit.yml")
    flat = list(_flat_tasks(plays))
    restart = next(n for n, (i, t) in enumerate(flat)
                   if "multihop-uplink-xray" in _dump(t) and "docker_container" in _dump(t)
                   and t.get("community.docker.docker_container", {}).get("state") == "started")
    task = flat[restart][1]
    assert task["community.docker.docker_container"]["restart"] is True
    assert "reality" in task["when"]
    wait = next(n for n, (i, t) in enumerate(flat) if "state established" in _dump(t))
    assert wait > restart
    w = flat[wait][1]
    assert "exit_reality_port" in _dump(w) and "reality" in w["when"]
    assert w["until"] and w["retries"] == 30 and w["delay"] == 10
    assert "curl" in _dump(w) and "amnezia-awg2" in _dump(w)
    # no handshake wait runs in reality mode
    for n, (i, t) in enumerate(flat):
        if "wait-handshake.yml" in _dump(t):
            assert "!= 'reality'" in str(t.get("when", "")) or "== 'awg'" in str(t.get("when", ""))


def test_verify_fail_closed_stops_uplink_xray_in_reality_mode():
    plays = _plays("playbooks/verify.yml")
    block = next(t for _, t in _flat_tasks(plays) if t.get("tags") == ["fail_closed"])
    container = block["vars"]["_fc_container"]
    assert "'multihop-uplink-xray' if uplink_transport == 'reality'" in container
    assert container.endswith("else 'multihop-uplink' }}")
    stop = [t for t in block["block"] if "docker_container" in _dump(t)]
    start = [t for t in block["always"] if "docker_container" in _dump(t)]
    assert stop[0]["community.docker.docker_container"] == {"name": "{{ _fc_container }}", "state": "stopped"}
    assert start[0]["community.docker.docker_container"] == {"name": "{{ _fc_container }}", "state": "started"}


SHARED_VARS = ("uplink_transport", "exit_reality_port", "uplink_reality_site",
               "uplink_tproxy_port", "entry_xray_enabled", "entry_xray_port")


def _role_applies_defaults(name, seen=()):
    if name == "multihop_defaults":
        return True
    meta = ROOT / "roles" / name / "meta" / "main.yml"
    if not meta.exists() or name in seen:
        return False
    deps = (yaml.safe_load(meta.read_text()) or {}).get("dependencies") or []
    return any(_role_applies_defaults(d["role"] if isinstance(d, dict) else d, (*seen, name))
               for d in deps)


def _task_text(play):
    """The play's own YAML plus every playbooks/tasks file it includes."""
    text = yaml.safe_dump({k: v for k, v in play.items() if k not in ("roles", "import_playbook")})
    for ref in __import__("re").findall(r"tasks/[\w.-]+\.yml", text):
        text += (ROOT / "playbooks" / ref).read_text()
    return text


def test_plays_using_shared_vars_apply_multihop_defaults():
    problems = []
    for path in sorted((ROOT / "playbooks").glob("*.yml")):
        for play in yaml.safe_load(path.read_text()):
            if "import_playbook" in play:
                continue
            text = _task_text(play) + yaml.safe_dump(play.get("roles") or [])
            if not any(v in text for v in SHARED_VARS):
                continue
            roles = [r["role"] if isinstance(r, dict) else r for r in play.get("roles") or []]
            if not any(_role_applies_defaults(r) for r in roles):
                problems.append(f"{path.name}: {play.get('name')}")
    assert not problems, problems


def test_roles_using_shared_vars_depend_on_multihop_defaults():
    for role in ("common", "exit", "entry_uplink"):
        assert _role_applies_defaults(role), role
