"""Restore validation for entry backups (controller side).

awg-quick runs PreUp/PostUp/PreDown/PostDown from awg0.conf as root, age
gives no authenticity and the recipient key is public, so a holder of the S3
writer key could plant a backup that runs code on the next restored entry.
A backup is accepted only if every member is a regular file directly at the
archive root and awg0.conf uses allow-listed keys, with the inventory's port
and subnet.

The entry Xray state sits under ./xray/: only the app's six file names, as
regular files, and a server.json of exactly the shape the Amnezia app writes
(one VLESS + REALITY inbound on entry_xray_port, one plain freedom outbound).
Anything else (routing, api, an extra inbound, a file-writing log, an
outbound to somewhere) could turn the privileged amnezia-xray container into
something else, so it is refused.
"""
import ipaddress
import json
import re
import tarfile

INTERFACE_KEYS = {
    "privatekey", "address", "listenport", "mtu",
    "jc", "jmin", "jmax", "s1", "s2", "s3", "s4", "h1", "h2", "h3", "h4",
    "i1", "i2", "i3", "i4", "i5",
    "headerprotectionkey", "contentpaddingaddition", "rekeyaftertime", "rekeytimeout",
    "rejectaftertime", "keepalivetimeout", "maxhandshakeattempts", "randomtrailers",
    "disablecookies",
}
PEER_KEYS = {"publickey", "presharedkey", "allowedips", "endpoint", "persistentkeepalive"}
SECTIONS = {"[Interface]": INTERFACE_KEYS, "[Peer]": PEER_KEYS}
REQUIRED = ("awg0.conf", "wireguard_server_private_key.key")

XRAY_DIR = "xray"
_UUID = r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"
_KEY = r"[A-Za-z0-9_-]{43}"  # X25519 key, base64url without padding (`xray x25519`)
# Key files hold one value and an optional trailing newline (printf '%s\n').
XRAY_KEY_FILES = {
    "xray_uuid.key": (_UUID, "a UUID"),
    "xray_private.key": (_KEY, "a 43-character base64url key"),
    "xray_public.key": (_KEY, "a 43-character base64url key"),
    "xray_short_id.key": (r"[0-9a-fA-F]{16}", "16 hex digits"),
}
XRAY_FILES = {"server.json", "clientsTable", *XRAY_KEY_FILES}
# entry_xray's restore needs these; clientsTable appears once the app adds a user.
XRAY_REQUIRED = ("server.json", *sorted(XRAY_KEY_FILES))
XRAY_LOGLEVELS = {"debug", "info", "warning", "error", "none"}


class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs):
    obj = {}
    for key, value in pairs:
        if key in obj:
            raise _DuplicateKey(f"duplicate key {key!r}")
        obj[key] = value
    return obj


def _strict_json(text):
    """json.loads that refuses duplicate keys at any level. json.loads keeps
    the last one, but Go's encoding/json (Xray) merges a duplicate object into
    the one already read, so a shape check of the last one would be bypassed."""
    return json.loads(text, object_pairs_hook=_no_duplicates)


# REALITY forwards unauthenticated probes to dest: it must be a public site
# name as the app writes it ("<site>:443"), never loopback, a private address
# or any IP literal.
_DEST = re.compile(r"(?=[A-Za-z0-9.-]*[A-Za-z])([A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+):443")


def _dest_ok(dest):
    if not isinstance(dest, str):
        return False
    m = _DEST.fullmatch(dest)
    if not m:
        return False
    host = m.group(1).lower()
    if host == "localhost" or host.endswith(".localhost"):
        return False
    try:
        ipaddress.ip_address(host)
    except ValueError:
        return True
    return False


def _parts(name):
    """Path components relative to the archive root, [] for the root itself,
    None for an absolute name or one with '', '.' or '..' components."""
    if name.startswith("/"):
        return None
    rel = name[2:] if name.startswith("./") else name
    rel = rel.rstrip("/")
    if rel in ("", "."):
        return []
    parts = rel.split("/")
    if any(p in ("", ".", "..") for p in parts):
        return None
    return parts


def _conf_problems(text, port, subnet):
    problems, section, seen = [], None, {"listenport": [], "address": []}
    for n, line in enumerate(text.splitlines(), 1):
        stripped = line.split("#", 1)[0].strip()  # as awg-quick: '#' starts a comment
        if not stripped:
            continue
        if stripped.startswith("["):
            if stripped not in SECTIONS:
                problems.append(f"awg0.conf line {n}: unknown section {stripped!r}")
                section = None
                continue
            section = stripped
            continue
        if "=" not in stripped:
            problems.append(f"awg0.conf line {n}: not a 'Key = value' line")
            continue
        key, value = (part.strip() for part in stripped.split("=", 1))
        if section is None:
            problems.append(f"awg0.conf line {n}: '{key}' outside a section")
            continue
        if key.lower() not in SECTIONS[section]:
            problems.append(f"awg0.conf line {n}: key '{key}' is not allowed in {section}")
            continue
        if section == "[Interface]" and key.lower() in seen:
            seen[key.lower()].append(value)
    ports = seen["listenport"]
    if ports != [str(port)]:
        problems.append(f"awg0.conf ListenPort {', '.join(ports) or '(missing)'} != entry_awg_port {port}")
    net = ipaddress.ip_network(subnet, strict=False)
    addrs = [a.strip() for v in seen["address"] for a in v.split(",") if a.strip()]
    if not addrs:
        problems.append(f"awg0.conf Address (missing) is not in entry_awg_subnet {subnet}")
    for addr in addrs:
        try:
            ok = ipaddress.ip_interface(addr).network == net
        except ValueError:
            ok = False
        if not ok:
            problems.append(f"awg0.conf Address {addr} is not in entry_awg_subnet {subnet}")
    return problems


def _keys_problems(obj, where, required, optional=()):
    """Problems if dict `obj` lacks a required key or has one outside required + optional."""
    if not isinstance(obj, dict):
        return [f"{where} must be a JSON object"]
    problems = [f"{where}: '{k}' is not allowed" for k in sorted(set(obj) - set(required) - set(optional))]
    problems += [f"{where}: '{k}' is missing" for k in required if k not in obj]
    return problems


def _is_int(value):
    return isinstance(value, int) and not isinstance(value, bool)


def _str_list(value, pattern):
    return isinstance(value, list) and all(isinstance(v, str) and re.fullmatch(pattern, v)
                                           for v in value)


def _inbound_problems(inbound, port):
    w = "xray/server.json inbounds[0]"
    problems = _keys_problems(inbound, w, ("port", "protocol", "settings", "streamSettings"))
    if not isinstance(inbound, dict):
        return problems
    if "protocol" in inbound and inbound["protocol"] != "vless":
        problems.append(f"{w}: protocol must be 'vless'")
    if "port" in inbound:
        if not _is_int(inbound["port"]):
            problems.append(f"{w}: port must be a number")
        elif port is not None and inbound["port"] != int(port):
            problems.append(f"xray/server.json port {inbound['port']} != entry_xray_port {port}")

    settings = inbound.get("settings", {})
    problems += _keys_problems(settings, f"{w}.settings", ("clients", "decryption"))
    if isinstance(settings, dict):
        if "decryption" in settings and settings["decryption"] != "none":
            problems.append(f"{w}.settings: decryption must be 'none'")
        clients = settings.get("clients", [])
        if not isinstance(clients, list):
            problems.append(f"{w}.settings: clients must be a list")
            clients = []
        for n, client in enumerate(clients):
            cw = f"{w}.settings.clients[{n}]"
            problems += _keys_problems(client, cw, ("id", "flow"))
            if not isinstance(client, dict):
                continue
            if "id" in client and not (isinstance(client["id"], str) and re.fullmatch(_UUID, client["id"])):
                problems.append(f"{cw}: id must be a UUID")
            if "flow" in client and client["flow"] not in ("xtls-rprx-vision", ""):
                problems.append(f"{cw}: flow must be 'xtls-rprx-vision'")

    stream = inbound.get("streamSettings", {})
    sw = f"{w}.streamSettings"
    problems += _keys_problems(stream, sw, ("security", "realitySettings"), ("network",))
    if isinstance(stream, dict):
        if "security" in stream and stream["security"] != "reality":
            problems.append(f"{sw}: security must be 'reality'")
        if stream.get("network", "tcp") not in ("tcp", "raw"):
            problems.append(f"{sw}: network must be 'tcp'")
        reality = stream.get("realitySettings", {})
        rw = f"{sw}.realitySettings"
        problems += _keys_problems(reality, rw, ("dest", "privateKey", "serverNames", "shortIds"))
        if isinstance(reality, dict):
            # The app builds dest as "<site>:443"; no sockets, no other ports.
            if "dest" in reality and not _dest_ok(reality["dest"]):
                problems.append(f"{rw}: dest must be '<public site name>:443' "
                                "(no IP literal, localhost or private address)")
            if "privateKey" in reality and not (isinstance(reality["privateKey"], str)
                                                and re.fullmatch(r"[A-Za-z0-9_=+/-]+", reality["privateKey"])):
                problems.append(f"{rw}: privateKey must be a key string")
            if "serverNames" in reality and not _str_list(reality["serverNames"], r"[A-Za-z0-9.-]+"):
                problems.append(f"{rw}: serverNames must be a list of host names")
            if "shortIds" in reality and not _str_list(reality["shortIds"], r"[0-9a-fA-F]{0,16}"):
                problems.append(f"{rw}: shortIds must be a list of hex strings")
    return problems


def xray_server_json_problems(text, port):
    """Reasons to refuse the backed-up server.json `text` (empty = ok).

    It must have exactly the shape the Amnezia app (5.1.0.6) writes. `port`
    is entry_xray_port; None skips only the port comparison (Xray disabled:
    the file is not restored).
    """
    try:
        cfg = _strict_json(text)
    except _DuplicateKey as exc:
        return [f"xray/server.json has a {exc} (refused: Xray would merge it)"]
    except ValueError as exc:
        return [f"xray/server.json is not valid JSON ({exc})"]
    w = "xray/server.json"
    if not isinstance(cfg, dict):
        return [f"{w} must be a JSON object"]
    problems = [f"{w}: section '{k}' is not allowed" for k in sorted(set(cfg) - {"log", "inbounds", "outbounds"})]
    problems += [f"{w}: section '{k}' is missing" for k in ("log", "inbounds", "outbounds") if k not in cfg]

    # log.access/log.error would write files anywhere in the privileged container.
    if "log" in cfg:
        log = cfg["log"]
        if not (isinstance(log, dict) and set(log) == {"loglevel"} and log["loglevel"] in XRAY_LOGLEVELS):
            problems.append(f"{w}: log must be just {{\"loglevel\": <level>}}")
    if "inbounds" in cfg:
        inbounds = cfg["inbounds"]
        if not (isinstance(inbounds, list) and len(inbounds) == 1):
            problems.append(f"{w}: must have exactly one inbound")
        else:
            problems += _inbound_problems(inbounds[0], port)
    if "outbounds" in cfg and cfg["outbounds"] != [{"protocol": "freedom"}]:
        problems.append(f"{w}: outbounds must be exactly [{{\"protocol\": \"freedom\"}}]")
    return problems


def _xray_file_problems(name, data, xray_port):
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return [f"xray/{name} is not UTF-8 text"]
    if name == "server.json":
        return xray_server_json_problems(text, xray_port)
    if name == "clientsTable":
        try:
            _strict_json(text)
        except _DuplicateKey as exc:
            return [f"xray/clientsTable has a {exc}"]
        except ValueError as exc:
            return [f"xray/clientsTable is not valid JSON ({exc})"]
        return []
    pattern, what = XRAY_KEY_FILES[name]
    if not re.fullmatch(pattern + r"\n?", text):
        return [f"xray/{name} must be a single line holding {what}"]
    return []


def backup_archive_problems(path, port, subnet, xray_port=None, skip_xray=False):
    """Return a list of reasons to refuse the decrypted backup tar at `path` (empty = ok).

    `xray_port` is entry_xray_port, compared with the port in xray/server.json;
    None skips only that comparison (Xray disabled, xray/ is not restored).
    `skip_xray` (restore_skip_xray) ignores every member under xray/ (the
    caller leaves them out of what it restores); odd paths are still refused.
    """
    problems, names, conf, xray, unknown_xray = [], set(), None, {}, False
    try:
        tar = tarfile.open(path, "r:")
    except (tarfile.TarError, OSError) as exc:
        return [f"not a readable tar archive ({exc})"]
    with tar:
        for m in tar.getmembers():
            parts = _parts(m.name)
            if skip_xray and parts and parts[0] == XRAY_DIR:
                continue
            if parts is None or (len(parts) > 1 and parts[0] != XRAY_DIR):
                problems.append(f"member {m.name!r} is not directly at the archive root")
                continue
            if len(parts) > 2:
                problems.append(f"member {m.name!r} is nested inside xray/ (only files directly in xray/)")
                continue
            rel = "/".join(parts)
            if rel in ("", XRAY_DIR):
                if not m.isdir():
                    what = "the root directory" if rel == "" else "a directory"
                    problems.append(f"member {m.name!r} must be {what}")
                elif rel in names:
                    problems.append(f"duplicate member {m.name!r}")
                names.add(rel)
                continue
            if not m.isreg():
                problems.append(f"member {m.name!r} is not a regular file")
                continue
            if rel in names:
                problems.append(f"duplicate member {m.name!r}")
                continue
            names.add(rel)
            if rel == "awg0.conf":
                conf = tar.extractfile(m).read()
            elif parts[0] == XRAY_DIR:
                if parts[1] not in XRAY_FILES:
                    problems.append(f"member {m.name!r} is not an allowed Xray file")
                    unknown_xray = True
                    continue
                xray[parts[1]] = tar.extractfile(m).read()
    for req in REQUIRED:
        if req not in names:
            problems.append(f"{req} is missing at the archive root")
    if conf is not None:
        try:
            problems += _conf_problems(conf.decode("utf-8"), port, subnet)
        except UnicodeDecodeError:
            problems.append("awg0.conf is not UTF-8 text")
    if XRAY_DIR in names or any(n.startswith(XRAY_DIR + "/") for n in names):
        for req in XRAY_REQUIRED:
            if f"{XRAY_DIR}/{req}" not in names:
                problems.append(f"xray/{req} is missing")
        for name in sorted(xray):
            problems += _xray_file_problems(name, xray[name], xray_port)
    if unknown_xray:
        problems.append(f"xray/ may hold only {', '.join(sorted(XRAY_FILES))}")
    return problems


class FilterModule:
    def filters(self):
        return {"backup_archive_problems": backup_archive_problems,
                "xray_server_json_problems": xray_server_json_problems}
