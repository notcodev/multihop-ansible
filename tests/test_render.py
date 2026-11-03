"""Template render harness: renders role templates with fixture vars."""
import json
import os
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
RENDER_DIR = ROOT / "tests" / "render"
FIXTURE_VAULT_PASS = ROOT / "tests" / "fixtures" / "vault-pass"


def render(src: str, dest: str, extra_vars: dict | None = None) -> str:
    """Render `src` (repo-root relative or absolute) and return the text."""
    src_path = Path(src)
    if not src_path.is_absolute():
        src_path = ROOT / src_path
    env = dict(os.environ)
    if not (ROOT / ".vault-pass").exists():
        env.setdefault("ANSIBLE_VAULT_PASSWORD_FILE", str(FIXTURE_VAULT_PASS))
    env["ANSIBLE_CONFIG"] = str(ROOT / "ansible.cfg")
    # Explicit localhost-only inventory: no inventory group_vars/vault load.
    # ansible.cfg uses repo-relative paths, so run from the repo root.
    payload = {"render_list": [{"src": str(src_path), "dest": dest}]}
    payload.update(extra_vars or {})
    out = RENDER_DIR / "out" / dest
    out.unlink(missing_ok=True)
    proc = subprocess.run(
        ["ansible-playbook", "-i", "localhost,", "-e", "ansible_connection=local",
         str(RENDER_DIR / "render.yml"), "-e", json.dumps(payload)],
        cwd=ROOT, env=env, capture_output=True, text=True,
    )
    assert proc.returncode == 0, proc.stdout + proc.stderr
    return out.read_text()


def test_env_template_renders_public_iface():
    text = render("roles/common/templates/multihop.env.j2", "multihop.env")
    assert "PUBLIC_IFACE=eth0" in text
    assert "SSH_PORT=22" in text


def test_extra_vars_override_fixture():
    text = render("roles/common/templates/multihop.env.j2", "multihop.env",
                  {"public_iface": "ens3"})
    assert "PUBLIC_IFACE=ens3" in text


def test_input_udp_ports_from_common_input_udp_ports():
    text = render("roles/common/templates/multihop.env.j2", "multihop.env",
                  {"common_input_udp_ports": [51820, 51821]})
    assert 'INPUT_UDP_PORTS="51820 51821"' in text


def test_input_tcp_ports_combines_common_and_extra():
    text = render("roles/common/templates/multihop.env.j2", "multihop.env",
                  {"common_input_tcp_ports": [443], "extra_input_tcp_ports": [8080]})
    assert 'INPUT_TCP_PORTS="443 8080"' in text


def _fixture():
    import yaml
    return yaml.safe_load((RENDER_DIR / "fixture_vars.yml").read_text())


def test_exit_conf():
    fx = _fixture()
    text = render("roles/exit/templates/awg-exit.conf.j2", "awg-exit.conf")
    link, uplink = fx["vault_link_awg"], fx["vault_uplink_entry"]
    iface, peer = text.split("[Peer]")
    assert text.count("[Peer]") == 1 and iface.lstrip().startswith("[Interface]")
    assert f"PrivateKey = {link['exit_private_key']}" in iface
    assert "Address = 10.9.0.1/30" in iface
    assert f"ListenPort = {fx['exit_awg_port']}" in iface
    assert "Table = off" in iface
    assert "MTU = 1280" in iface
    assert "Jc = 6" in iface
    assert f"# I1 = {link['params']['i1']}" in iface
    assert not any(ln.startswith("I1") for ln in text.splitlines())
    assert f"PublicKey = {uplink['public_key']}" in peer
    assert f"PresharedKey = {link['psk']}" in peer
    assert "AllowedIPs = 10.9.0.2/32" in peer
    assert "Endpoint" not in text


def test_exit_conf_other_subnet():
    text = render("roles/exit/templates/awg-exit.conf.j2", "awg-exit.conf",
                  {"uplink_subnet": "192.168.7.4/30"})
    assert "Address = 192.168.7.5/30" in text
    assert "AllowedIPs = 192.168.7.6/32" in text


def test_awg0_conf_matches_app_layout():
    fx = _fixture()
    text = render("roles/entry_app/templates/awg0.conf.j2", "awg0.conf")
    lines = [ln for ln in text.splitlines() if ln.strip()]
    key = fx["vault_entry_awg"]["private_key"]
    assert lines[:4] == [
        "[Interface]",
        f"PrivateKey = {key}",
        "Address = 10.8.1.1/24",
        f"ListenPort = {fx['entry_awg_port']}",
    ]
    assert lines[4] == "Jc = 4"
    assert f"# I1 = {fx['vault_entry_awg']['params']['i1']}" in lines
    assert not any(ln.startswith("I1") for ln in lines)
    assert "[Peer]" not in text
    for ln in lines[1:]:
        assert " = " in ln.lstrip("# ")


def test_awg0_conf_other_subnet():
    text = render("roles/entry_app/templates/awg0.conf.j2", "awg0.conf",
                  {"entry_awg_subnet": "10.20.30.0/23"})
    assert "Address = 10.20.30.1/23" in text


def test_start_sh_substitutes_subnet():
    text = render("roles/entry_app/templates/start.sh.j2", "start.sh")
    assert "-s 10.8.1.0/24 -o eth0 -j MASQUERADE" in text
    assert "-s 10.8.1.0/24 -o eth1 -j MASQUERADE" in text
    assert "$AWG_SUBNET_IP" not in text
    assert "$WIREGUARD_SUBNET_CIDR" not in text


def test_uplink_conf():
    fx = _fixture()
    text = render("roles/entry_uplink/templates/awg-uplink.conf.j2", "awg-uplink.conf")
    link, uplink = fx["vault_link_awg"], fx["vault_uplink_entry"]
    iface, peer = text.split("[Peer]")
    assert text.count("[Peer]") == 1 and iface.lstrip().startswith("[Interface]")
    assert f"PrivateKey = {uplink['private_key']}" in iface
    assert "Address = 10.9.0.2/30" in iface
    assert "Table = off" in iface
    assert "MTU = 1280" in iface
    assert "PostUp = ip route replace default dev %i table 51820 metric 1" in iface
    assert "ListenPort" not in text
    assert "Jc = 6" in iface
    assert f"\nI1 = {link['params']['i1']}\n" in iface
    assert "# I1" not in text
    assert f"PublicKey = {link['exit_public_key']}" in peer
    assert f"PresharedKey = {link['psk']}" in peer
    assert "AllowedIPs = 0.0.0.0/0" in peer
    assert f"Endpoint = exit.example.com:{fx['exit_awg_port']}" in peer
    assert "PersistentKeepalive = 25" in peer


def test_uplink_conf_other_subnet():
    text = render("roles/entry_uplink/templates/awg-uplink.conf.j2", "awg-uplink.conf",
                  {"uplink_subnet": "192.168.7.4/30", "uplink_mtu": 1360})
    assert "Address = 192.168.7.6/30" in text
    assert "MTU = 1360" in text


def _unit(text: str) -> dict:
    """Parse a systemd unit into {section: [(key, value), ...]}."""
    out, sec = {}, None
    for ln in text.splitlines():
        ln = ln.strip()
        if not ln or ln.startswith("#"):
            continue
        if ln.startswith("["):
            sec = ln.strip("[]")
            out.setdefault(sec, [])
        else:
            k, v = ln.split("=", 1)
            out[sec].append((k, v))
    return out


def _vals(unit: dict, sec: str, key: str) -> list:
    return [w for k, v in unit.get(sec, []) if k == key for w in v.split()]


def test_entry_net_unit_runs_before_docker():
    """Review Focus 2: rules exist before Docker restarts amnezia-awg2."""
    u = _unit(render("roles/entry_uplink/templates/multihop-net.service.j2",
                     "multihop-net.service"))
    assert "docker.service" in _vals(u, "Unit", "Before")
    assert "docker.service" not in _vals(u, "Unit", "After")
    for key in ("PartOf", "Requires", "BindsTo", "Wants"):
        assert "docker.service" not in _vals(u, "Unit", key)
    assert _vals(u, "Service", "Type") == ["oneshot"]
    assert _vals(u, "Service", "RemainAfterExit") == ["yes"]
    assert _vals(u, "Service", "ExecStart") == ["/usr/local/sbin/multihop-entry-net", "up"]
    assert _vals(u, "Service", "ExecReload") == ["/usr/local/sbin/multihop-entry-net", "up"]
    # stopping the unit must never tear down the fail-closed rules
    assert _vals(u, "Service", "ExecStop") == []
    assert _vals(u, "Install", "WantedBy") == ["multi-user.target"]


def test_docker_dropin_pulls_in_entry_net():
    u = _unit((ROOT / "roles/entry_uplink/files/docker-multihop.conf").read_text())
    assert "multihop-net.service" in _vals(u, "Unit", "Wants")
    assert "multihop-net.service" in _vals(u, "Unit", "After")


def test_reresolve_timer_every_minute():
    u = _unit(render("roles/entry_uplink/templates/multihop-reresolve.timer.j2",
                     "multihop-reresolve.timer"))
    assert _vals(u, "Timer", "OnUnitActiveSec") == ["1min"]
    assert _vals(u, "Timer", "OnBootSec")
    assert _vals(u, "Install", "WantedBy") == ["timers.target"]
    s = _unit(render("roles/entry_uplink/templates/multihop-reresolve.service.j2",
                     "multihop-reresolve.service"))
    assert _vals(s, "Service", "Type") == ["oneshot"]
    assert _vals(s, "Service", "ExecStart") == ["/usr/local/sbin/multihop-reresolve"]


def test_uplink_start_sh():
    text = render("roles/entry_uplink/templates/uplink-start.sh.j2", "uplink-start.sh")
    assert "CONF=/etc/amnezia/awg-uplink.conf" in text
    assert "trap down TERM INT" in text
    assert 'awg-quick up "$CONF"' in text


def _udp_masq_range(text: str, iface: str) -> tuple[int, int]:
    """Return the --to-ports range of the UDP MASQUERADE rule for iface and
    assert it precedes the app's generic MASQUERADE rule for the same iface."""
    lines = text.splitlines()
    generic = f"iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o {iface} -j MASQUERADE"
    udp_prefix = f"iptables -t nat -A POSTROUTING -s 10.8.1.0/24 -o {iface} -p udp -j MASQUERADE --to-ports "
    gi = lines.index(generic)  # app line kept verbatim
    ui = [i for i, ln in enumerate(lines) if ln.startswith(udp_prefix)]
    assert len(ui) == 1 and ui[0] < gi
    lo, hi = lines[ui[0]][len(udp_prefix):].split("-")
    return int(lo), int(hi)


@pytest.mark.parametrize("port, expected", [
    (51470, (1024, 51469)),   # fixture port: everything below it
    (65535, (1024, 65534)),   # top end
    (11025, (1024, 11024)),   # exactly 10000 ports below
    (11024, (11025, 65535)),  # one short: use the range above
    (1500, (1501, 65535)),    # bottom end
])
def test_start_sh_udp_masquerade_excludes_awg_port(port, expected):
    text = render("roles/entry_app/templates/start.sh.j2", "start.sh",
                  {"entry_awg_port": port})
    for iface in ("eth0", "eth1"):
        lo, hi = _udp_masq_range(text, iface)
        assert (lo, hi) == expected
        assert not lo <= port <= hi
        assert hi - lo + 1 >= 10000


def test_public_iface_group_udev_rule_matches_the_mac():
    # The group rule 10120 suppresses must survive a NIC rename/re-creation.
    text = render("roles/entry_uplink/templates/90-multihop-public-group.rules.j2",
                  "90-multihop-public-group.rules",
                  {"ansible_default_ipv4": {"macaddress": "52:54:00:12:34:56"}})
    rules = [line for line in text.splitlines() if line and not line.startswith("#")]
    assert rules == ['ACTION=="add|move", SUBSYSTEM=="net", ATTR{address}=="52:54:00:12:34:56", '
                     'RUN+="/usr/sbin/ip link set dev $name group 51820"']


def test_exit_xray_config():
    import json
    import yaml
    fx = yaml.safe_load((RENDER_DIR / "fixture_vars.yml").read_text())
    text = render("roles/exit/templates/xray-exit.json.j2", "xray-exit.json",
                  {"ansible_host": "198.51.100.7"})
    cfg = json.loads(text)
    (inb,) = cfg["inbounds"]
    assert inb["port"] == 443 and inb["protocol"] == "vless"
    assert inb["settings"]["decryption"] == "none"
    assert inb["settings"]["clients"] == [
        {"id": fx["vault_uplink_entry"]["reality_uuid"], "flow": "xtls-rprx-vision"}]
    ss = inb["streamSettings"]
    # Xray 26 docs name the transport field `method` (default raw).
    assert ss["method"] == "raw" and ss["security"] == "reality"
    rs = ss["realitySettings"]
    assert rs["target"] == "dl.google.com:443"
    assert rs["serverNames"] == ["dl.google.com"]
    assert rs["privateKey"] == fx["vault_link_reality"]["private_key"]
    assert rs["shortIds"] == [fx["vault_link_reality"]["short_id"]]
    for key in ("limitFallbackUpload", "limitFallbackDownload"):
        assert rs[key]["afterBytes"] > 0 and rs[key]["bytesPerSec"] > 0
    (out,) = cfg["outbounds"]
    assert out["protocol"] == "freedom"
    assert out["settings"]["finalRules"] == [
        {"action": "block", "ip": ["169.254.0.0/16", "10.0.0.0/8", "172.16.0.0/12",
                                   "192.168.0.0/16", "100.64.0.0/10", "127.0.0.0/8",
                                   "198.51.100.7/32"]},
        {"action": "allow"}]
    assert "redirect" not in out["settings"]


def test_uplink_xray_config():
    import json
    import yaml
    fx = yaml.safe_load((RENDER_DIR / "fixture_vars.yml").read_text())
    text = render("roles/entry_uplink/templates/xray-uplink.json.j2", "xray-uplink.json",
                  {"uplink_tproxy_port": 12345})
    cfg = json.loads(text)
    (inb,) = cfg["inbounds"]
    assert inb["listen"] == "127.0.0.1" and inb["port"] == 12345
    assert inb["protocol"] == "tunnel"
    # Xray 26 docs name the tunnel's network list `allowedNetwork`.
    assert inb["settings"]["allowedNetwork"] == "tcp,udp"
    assert inb["settings"]["followRedirect"] is True
    assert inb["streamSettings"]["sockopt"]["tproxy"] == "tproxy"
    assert "sniffing" not in inb or inb["sniffing"]["enabled"] is False
    (out,) = cfg["outbounds"]
    assert out["protocol"] == "vless"
    (vnext,) = out["settings"]["vnext"]
    assert vnext["address"] == fx["exit_domain"] and vnext["port"] == 443
    (user,) = vnext["users"]
    assert user == {"id": fx["vault_uplink_entry"]["reality_uuid"],
                    "flow": "xtls-rprx-vision", "encryption": "none"}
    ss = out["streamSettings"]
    assert ss["method"] == "raw" and ss["security"] == "reality"
    assert ss["realitySettings"] == {
        "serverName": "dl.google.com", "fingerprint": "chrome",
        "password": fx["vault_link_reality"]["public_key"],
        "shortId": fx["vault_link_reality"]["short_id"]}
    assert not [o for o in cfg["outbounds"] if o["protocol"] in ("freedom", "blackhole")]
    assert cfg["policy"]["levels"]["0"]["connIdle"] >= 300
