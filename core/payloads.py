"""
core/payloads.py

Safe payload generation utilities for authorized testing, fuzzing, and unit/integration tests.

WARNING:
- This module intentionally avoids providing exploit-specific payloads or attack tooling.
- Use only in environments you control or where you have explicit authorization.
"""

from __future__ import annotations
import os
import json
import random
import string
import secrets
import base64
import typing as t
from dataclasses import dataclass, asdict

# ---------- Types & Data Classes ----------

@dataclass
class Payload:
    name: str
    description: str
    content: str

    def to_dict(self) -> dict:
        return asdict(self)


# ---------- Built-in (benign) payload templates ----------

# These are safe examples intended for defensive testing (unit tests, parsers, encoders).
_BUILTIN_PAYLOADS: t.Dict[str, Payload] = {
    "heartbeat": Payload(
        name="heartbeat",
        description="Simple heartbeat string used for connectivity/echo tests.",
        content="ping"
    ),
    "long_string_1k": Payload(
        name="long_string_1k",
        description="A long ASCII string (~1,024 chars) used to test buffer handling.",
        content="".join(random.choice(string.ascii_letters + string.digits) for _ in range(1024))
    ),
    "unicode_stress": Payload(
        name="unicode_stress",
        description="String containing a range of Unicode code points for encoding tests.",
        content="".join(chr(i) for i in [0x00A9, 0x03A9, 0x20AC, 0x1F600, 0x1F4A9])  # © Ω € 😀 💩
    ),
    "json_sample": Payload(
        name="json_sample",
        description="Small JSON sample for parser tests.",
        content=json.dumps({"status": "ok", "count": 3, "items": ["a", "b", "c"]})
    )
}


# ---------- Helper utilities ----------

def list_builtin_payloads() -> t.List[str]:
    """Return names of built-in payload templates."""
    return list(_BUILTIN_PAYLOADS.keys())


def get_builtin_payload(name: str) -> t.Optional[Payload]:
    """Return a built-in payload by name or None if not found."""
    return _BUILTIN_PAYLOADS.get(name)


def save_payload_to_file(payload: Payload, path: str, overwrite: bool = False) -> None:
    """Save a payload to disk in JSON format. Raises if file exists and overwrite is False."""
    if os.path.exists(path) and not overwrite:
        raise FileExistsError(f"{path} already exists. Use overwrite=True to replace.")
    with open(path, "w", encoding="utf-8") as f:
        json.dump(payload.to_dict(), f, ensure_ascii=False, indent=2)


def load_payload_from_file(path: str) -> Payload:
    """Load a payload saved with save_payload_to_file."""
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return Payload(name=data["name"], description=data.get("description", ""), content=data.get("content", ""))


# ---------- Generators (safe / non-destructive) ----------

def generate_random_ascii(length: int = 64) -> str:
    """Generate a secure-random ASCII string (letters + digits)."""
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(max(0, length)))


def generate_fuzz_string(length: int = 256, include_binary: bool = False) -> bytes:
    """
    Generate a fuzzing payload as bytes.

    - include_binary: if True, include arbitrary bytes (0-255); otherwise ASCII printable.
    """
    if length <= 0:
        return b""
    if include_binary:
        return bytes(secrets.randbelow(256) for _ in range(length))
    else:
        alphabet = string.printable  # includes whitespace, digits, letters and punctuation
        return "".join(secrets.choice(alphabet) for _ in range(length)).encode("utf-8")


def generate_boundary_values() -> t.Dict[str, t.Union[str, bytes]]:
    """
    Return common boundary test values used in defensive tests:
    - empty, single char, long, very long, whitespace, null bytes, repeated char
    """
    return {
        "empty": "",
        "single_char": "A",
        "long_1k": "A" * 1024,
        "very_long_1M": "A" * (1024 * 1024),  # caution: large allocation
        "whitespace": " \t\n\r",
        "null_bytes": b"\x00" * 16,
        "repeated_pattern": ("ABCD" * 256)
    }


# ---------- Encoding / formatting helpers ----------

def to_base64(data: t.Union[str, bytes]) -> str:
    """Return base64-encoded string; accepts str (utf-8) or bytes."""
    if isinstance(data, str):
        data = data.encode("utf-8")
    return base64.b64encode(data).decode("ascii")


def from_base64(b64: str) -> bytes:
    """Decode base64 string to bytes, raises binascii.Error on invalid input."""
    return base64.b64decode(b64)


def url_encode(s: str) -> str:
    """Percent-encode a string for safe inclusion in URLs (left minimal to stdlib use)."""
    from urllib.parse import quote
    return quote(s, safe="")


def json_wrap(obj: t.Any) -> str:
    """Return a compact JSON string for a Python object."""
    return json.dumps(obj, separators=(",", ":"), ensure_ascii=False)


# ---------- Small utilities for test harnesses ----------

def make_payload(name: str, description: str, content: t.Union[str, bytes]) -> Payload:
    """Construct a Payload object. Bytes will be base64-encoded into the content field."""
    if isinstance(content, bytes):
        content_str = to_base64(content)
    else:
        content_str = str(content)
    return Payload(name=name, description=description, content=content_str)


def build_http_get_template(host: str, path: str = "/", query: t.Optional[dict] = None) -> str:
    """Return a simple HTTP GET request string (for use in unit tests / parsers)."""
    q = ""
    if query:
        from urllib.parse import urlencode
        q = "?" + urlencode(query)
    path_norm = path if path.startswith("/") else "/" + path
    return f"GET {path_norm}{q} HTTP/1.1\r\nHost: {host}\r\nUser-Agent: XVector-Pro-Test/1.0\r\nConnection: close\r\n\r\n"


# ---------- Small CLI-style helper for quick local checks ----------

def quick_demo_payloads() -> t.List[Payload]:
    """Return a small list of demo payloads (builtins and generated) for quick experimentation."""
    demos = []
    demos.append(get_builtin_payload("heartbeat"))
    demos.append(get_builtin_payload("json_sample"))
    demos.append(make_payload("random_ascii_128", "Random ASCII test string", generate_random_ascii(128)))
    demos.append(make_payload("fuzz_256_printable", "Fuzz (printable) 256 bytes", generate_fuzz_string(256, include_binary=False)))
    return [p for p in demos if p is not None]


# ---------- Module self-test when run directly ----------

if __name__ == "__main__":
    # Small, non-destructive demonstration
    print("Builtin payloads:", list_builtin_payloads())
    demo = quick_demo_payloads()
    for p in demo:
        print(f"--- {p.name} ({len(p.content)} chars) ---")
        print((p.content[:200] + "...") if len(p.content) > 200 else p.content)

    # boundary values (do not show very large content)
    bv = generate_boundary_values()
    for k, v in bv.items():
        size = len(v) if isinstance(v, (str, bytes)) else "?"
        print(f"boundary {k}: size={size}")
