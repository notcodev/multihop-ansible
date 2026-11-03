import importlib.util
import subprocess
import sys
import uuid
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("awg", ROOT / "plugins" / "filter" / "awg.py")
awg = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(awg)
_xspec = importlib.util.spec_from_file_location("xray", ROOT / "plugins" / "filter" / "xray.py")
xray = importlib.util.module_from_spec(_xspec)
_xspec.loader.exec_module(xray)


def run(arg):
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen-secrets.py"), arg],
        capture_output=True, text=True, check=True,
    ).stdout


def test_all_outputs_valid_vault_doc():
    out = run("all")
    assert out.startswith("# Suggested ports")
    doc = yaml.safe_load(out)
    for k in ("vault_entry_awg", "vault_link_awg", "vault_backup_writer",
              "vault_backup_reader", "vault_backup_age_identity",
              "vault_link_reality", "vault_entry_xray"):
        assert k in doc
    e, link = doc["vault_entry_awg"], doc["vault_link_awg"]
    assert e["params"]["header_protection_key"] != link["params"]["header_protection_key"]
    assert e["public_key"] == awg.pubkey(e["private_key"])
    assert link["exit_public_key"] == awg.pubkey(link["exit_private_key"])
    assert all(isinstance(v, str) for v in e["params"].values())
    assert doc["vault_backup_writer"] == {"access_key": "CHANGE_ME", "secret_key": "CHANGE_ME"}
    assert doc["vault_backup_age_identity"] == "CHANGE_ME"
    assert set(doc["vault_link_reality"]) == {"private_key", "public_key", "short_id"}
    assert set(doc["vault_entry_xray"]) == {"uuid", "private_key", "public_key", "short_id"}
    ports = [int(p) for p in out.splitlines()[0].replace(",", " ").split() if p.isdigit()]
    assert len(ports) == 2 and ports[0] != ports[1]
    assert all(20000 <= p <= 60000 for p in ports)


def test_uplink_key_doc():
    doc = yaml.safe_load(run("uplink-key"))
    u = doc["vault_uplink_entry"]
    assert u["public_key"] == awg.pubkey(u["private_key"])
    assert str(uuid.UUID(u["reality_uuid"], version=4)) == u["reality_uuid"]


def test_xray_subcommand_doc():
    doc = yaml.safe_load(run("xray"))
    assert set(doc) == {"vault_link_reality", "vault_entry_xray"}
    link, entry = doc["vault_link_reality"], doc["vault_entry_xray"]
    assert set(link) == {"private_key", "public_key", "short_id"}
    assert set(entry) == {"uuid", "private_key", "public_key", "short_id"}
    for block in (link, entry):
        assert block["public_key"] == xray.reality_pubkey(block["private_key"])
    assert str(uuid.UUID(entry["uuid"], version=4)) == entry["uuid"]
    values = list(link.values()) + list(entry.values())
    assert len(set(values)) == len(values)
