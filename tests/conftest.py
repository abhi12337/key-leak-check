"""Shared helpers. Fake secrets are random text assembled at runtime from a fixed seed,
so no secret-shaped string is ever committed to this repository (keeps secret scanners
quiet). None of them work anywhere."""

from __future__ import annotations

import base64
import json
import random
import shutil
import string
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"
_RNG = random.Random(4242)
ALNUM = string.ascii_letters + string.digits
HEX = "0123456789abcdef"


def _r(n: int, alphabet: str = ALNUM) -> str:
    return "".join(_RNG.choice(alphabet) for _ in range(n))


def _b64(obj) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def fake_jwt(role: str, iss: str = "supabase") -> str:
    payload = {"iss": iss, "ref": _r(20, string.ascii_lowercase), "role": role, "iat": 1760000000, "exp": 2075000000}
    return f"{_b64({'alg': 'HS256', 'typ': 'JWT'})}.{_b64(payload)}.{_r(43, ALNUM + '_-')}"


FAKE = {
    "openai": "sk-" + "proj-" + _r(120, ALNUM + "_-"),
    "anthropic": "sk-" + "ant-" + "api03-" + _r(93, ALNUM + "_-"),
    "gemini": "AI" + "za" + "Sy" + _r(33, ALNUM + "_-"),
    "groq": "gs" + "k_" + _r(52),
    "openrouter": "sk-" + "or-" + "v1-" + _r(64, HEX),
    "hf": "h" + "f_" + _r(34),
    "stripe_live": "sk_" + "live_" + _r(99),
    "stripe_test": "sk_" + "test_" + _r(99),
    "stripe_pk": "pk_" + "live_" + _r(99),
    "razorpay_id": "rz" + "p_live_" + _r(14),
    "razorpay_secret": _r(24),
    "service_jwt": fake_jwt("service" + "_role"),
    "anon_jwt": fake_jwt("anon"),
    "aws": "AK" + "IA" + _r(16, string.ascii_uppercase + string.digits),
    "aws_secret": _r(40, ALNUM + "/+"),
    "github": "gh" + "p_" + _r(36),
    "slack": "xo" + "xb-" + _r(12, string.digits) + "-" + _r(24),
    "sendgrid": "S" + "G." + _r(22, ALNUM + "_-") + "." + _r(43, ALNUM + "_-"),
    "resend": "r" + "e_" + _r(8) + "_" + _r(24),
    "twilio_token": _r(32, HEX),
    "db_password": _r(20),
    "firebase": "AI" + "za" + "Sy" + _r(33, ALNUM + "_-"),
    "generic": _r(40),
}
FAKE["db_url"] = f"postgresql://postgres.{_r(20, string.ascii_lowercase)}:{FAKE['db_password']}" \
                 f"@aws-0-ap-south-1.pooler.supabase.com:6543/postgres"
SECRET_KEYS = [k for k in FAKE if k not in ("stripe_pk", "razorpay_id", "anon_jwt", "firebase")]


@pytest.fixture
def fake():
    return FAKE


@pytest.fixture
def make_repo(tmp_path):
    """make_repo({"rel/path": "content", ...}, git=False, add=[...]) -> Path"""

    def _make(files: dict, *, git: bool = False, add: list[str] | None = None) -> Path:
        root = tmp_path / "repo"
        root.mkdir(exist_ok=True)
        for rel, content in files.items():
            p = root / rel
            p.parent.mkdir(parents=True, exist_ok=True)
            if isinstance(content, (dict, list)):
                content = json.dumps(content, indent=2)
            p.write_text(content, encoding="utf-8", newline="\n")
        if git:
            if shutil.which("git") is None:
                pytest.skip("git not installed")
            subprocess.run(["git", "init", "-q", str(root)], check=True)
            if add:
                subprocess.run(["git", "-C", str(root), "add", "-f", *add], check=True)
        return root

    return _make


@pytest.fixture
def copy_fixture(tmp_path):
    def _copy(name: str) -> Path:
        dst = tmp_path / name
        shutil.copytree(FIXTURES / name, dst)
        return dst

    return _copy
