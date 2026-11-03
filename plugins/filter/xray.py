"""Xray REALITY helpers and Ansible filters.

REALITY keys are X25519 keys encoded as base64url without padding, the
encoding `xray x25519` prints.
"""
import base64
import json
import random
import uuid

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def reality_genkey() -> str:
    return _b64u(X25519PrivateKey.generate().private_bytes(
        serialization.Encoding.Raw,
        serialization.PrivateFormat.Raw,
        serialization.NoEncryption(),
    ))


def reality_pubkey(priv: str) -> str:
    key = X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(priv + "="))
    return _b64u(key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ))


def gen_short_id(rng: random.Random) -> str:
    return f"{rng.getrandbits(64):016x}"


def gen_uuid() -> str:
    return str(uuid.uuid4())


def xray_port_range(awg_port: int) -> str:
    """Port range Xray may use as source on the host; same rule as entry_app start.sh.j2."""
    awg_port = int(awg_port)
    if awg_port - 1 - 1024 >= 10000:
        return f"1024 {awg_port - 1}"
    return f"{awg_port + 1} 65535"


def xray_server_json_port(text):
    """inbounds[0].port of an Xray server.json, or None if it cannot be read."""
    try:
        port = json.loads(text)["inbounds"][0]["port"]
    except (ValueError, TypeError, KeyError, IndexError):
        return None
    return port if isinstance(port, int) and not isinstance(port, bool) else None


class FilterModule:
    def filters(self):
        return {"xray_port_range": xray_port_range, "xray_server_json_port": xray_server_json_port}
