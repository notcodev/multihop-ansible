import base64
import importlib.util
import random
import re
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

_spec = importlib.util.spec_from_file_location(
    "xray", Path(__file__).resolve().parent.parent / "plugins" / "filter" / "xray.py"
)
xray = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(xray)


def _b64u(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def test_reality_key_roundtrip():
    k = xray.reality_genkey()
    assert len(k) == 43 and not set(k) & set("=+/")
    raw = base64.urlsafe_b64decode(k + "=")
    assert len(raw) == 32
    expected = X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    )
    assert xray.reality_pubkey(k) == _b64u(expected)


def test_reality_pubkey_known_vector():
    # RFC 7748 section 6.1, Alice; Xray REALITY keys use this same X25519 encoding.
    priv = bytes.fromhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
    pub = bytes.fromhex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a")
    assert xray.reality_pubkey(_b64u(priv)) == _b64u(pub)


def test_short_id_hex16():
    assert re.fullmatch(r"[0-9a-f]{16}", xray.gen_short_id(random.SystemRandom()))


def test_xray_port_range():
    assert xray.xray_port_range(51820) == "1024 51819"
    assert xray.xray_port_range(5000) == "5001 65535"
    assert xray.FilterModule().filters()["xray_port_range"] is xray.xray_port_range
