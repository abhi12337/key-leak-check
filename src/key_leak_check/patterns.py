"""Known secret token formats, secret-looking env var names, and the placeholder filter.

Everything here is precision-first: a pattern is only listed if its format is distinctive
enough that a match is almost certainly a real credential, and every match still goes
through `looks_like_placeholder` before it is reported."""

from __future__ import annotations

import base64
import json
import re
from dataclasses import dataclass

from .findings import PUBLIC_PREFIXES, entropy


@dataclass(frozen=True)
class TokenPattern:
    label: str
    provider: str
    regex: re.Pattern
    severity: str = "critical"      # in browser code / bundles; server-only code is one step lower
    prefix: re.Pattern | None = None  # stripped before the placeholder check


def _tp(label: str, provider: str, pattern: str, severity: str = "critical", prefix: str | None = None) -> TokenPattern:
    return TokenPattern(label, provider, re.compile(pattern), severity, re.compile(prefix) if prefix else None)


# Order matters: more specific formats first (sk-ant- before sk-, sk-or- before sk-).
TOKEN_PATTERNS: list[TokenPattern] = [
    _tp("Anthropic API key", "anthropic", r"\bsk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{32,}", prefix=r"^sk-ant-\w+-"),
    _tp("OpenRouter API key", "openrouter", r"\bsk-or-v1-[a-f0-9]{48,}", prefix=r"^sk-or-v1-"),
    _tp("OpenAI API key", "openai", r"\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_\-]{40,}", prefix=r"^sk-\w+-"),
    _tp("OpenAI API key (legacy)", "openai", r"\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b", prefix=r"^sk-"),
    _tp("Groq API key", "groq", r"\bgsk_[A-Za-z0-9]{40,}\b", prefix=r"^gsk_"),
    _tp("xAI API key", "xai", r"\bxai-[A-Za-z0-9]{60,}\b", prefix=r"^xai-"),
    _tp("Perplexity API key", "perplexity", r"\bpplx-[A-Za-z0-9]{40,}\b", prefix=r"^pplx-"),
    _tp("Replicate API token", "replicate", r"\br8_[A-Za-z0-9]{37}\b", prefix=r"^r8_"),
    _tp("Hugging Face token", "huggingface", r"\bhf_[A-Za-z0-9]{34,}\b", prefix=r"^hf_"),
    _tp("ElevenLabs API key", "elevenlabs", r"\bsk_[a-f0-9]{48}\b", prefix=r"^sk_"),
    _tp("Stripe live secret key", "stripe", r"\b[sr]k_live_[A-Za-z0-9]{20,}\b", prefix=r"^[sr]k_live_"),
    _tp("Stripe test secret key", "stripe", r"\b[sr]k_test_[A-Za-z0-9]{20,}\b", "medium", prefix=r"^[sr]k_test_"),
    _tp("Stripe webhook secret", "stripe", r"\bwhsec_[A-Za-z0-9]{32,}\b", "high", prefix=r"^whsec_"),
    _tp("Supabase secret key", "supabase", r"\bsb_secret_[A-Za-z0-9_\-]{20,}", prefix=r"^sb_secret_"),
    _tp("AWS access key id", "aws", r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", prefix=r"^A[KS]IA"),
    _tp("GitHub token", "github", r"\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})",
        prefix=r"^(?:gh[pousr]_|github_pat_)"),
    _tp("Slack token", "slack", r"\bxox[abposr]-[0-9]{6,}-[A-Za-z0-9\-]{10,}", prefix=r"^xox\w-"),
    _tp("SendGrid API key", "sendgrid", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b", prefix=r"^SG\."),
    _tp("Resend API key", "resend", r"\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{24,}\b", prefix=r"^re_"),
    _tp("Twilio API key", "twilio", r"\bSK[0-9a-f]{32}\b", "high", prefix=r"^SK"),
    _tp("npm token", "generic", r"\bnpm_[A-Za-z0-9]{36}\b", "high", prefix=r"^npm_"),
    _tp("Private key", "generic", r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
]

# Google API keys (AIza...) are also Firebase web keys, which are public by design. A
# Google key is only reported when Gemini / Generative Language is mentioned nearby.
RE_GOOGLE_KEY = re.compile(r"\bAIza[0-9A-Za-z_\-]{35}\b")
RE_GEMINI_CONTEXT = re.compile(r"(?i)gemini|generativelanguage|generative[_-]?ai|GoogleGenAI|genai")
RE_JWT = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")

# ---------------------------------------------------------------- publishable (never flagged)
RE_PUBLISHABLE_VALUE = re.compile(
    r"^(?:pk_(?:live|test)_|rzp_(?:live|test)_|sb_publishable_|AIza|pk\.ey|phc_|pub[a-f0-9]{32}$|"
    r"G-[A-Z0-9]{6,}$|UA-\d)"
)


def decode_jwt_payload(token: str) -> dict | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    seg = parts[1] + "=" * (-len(parts[1]) % 4)
    try:
        data = json.loads(base64.urlsafe_b64decode(seg.encode()).decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    return data if isinstance(data, dict) else None


def secret_jwt_role(token: str) -> str | None:
    """'service_role' / 'supabase_admin' for Supabase secret JWTs; None for anon and others."""
    payload = decode_jwt_payload(token)
    if not payload:
        return None
    role = str(payload.get("role", ""))
    if role in ("service_role", "supabase_admin") and payload.get("iss") != "supabase-demo":
        return role
    return None


# ---------------------------------------------------------------- placeholders
PLACEHOLDER_WORDS = re.compile(
    r"(?i)your|example|placeholder|replace|insert|changeme|change_me|dummy|redacted|sample|xxxx|"
    r"\.\.\.|<|>|\{\{|\$\{|todo|fixme|not[-_]?a[-_]?real|fake|^test$|mykey|my[-_]?key|secret_here|key_here"
)


def looks_like_placeholder(value: str, prefix: re.Pattern | None = None) -> bool:
    """Real keys are random: long, many distinct characters, no words or long runs."""
    body = prefix.sub("", value) if prefix else value
    if PLACEHOLDER_WORDS.search(value):
        return True
    if re.search(r"(.)\1{5,}", body):            # 000000, xxxxxx
        return True
    if re.search(r"(?i)0123456|123456789|abcdefgh|qwerty", body):
        return True
    if len(body) >= 16 and (len(set(body)) < 10 or entropy(body) < 3.0):
        return True
    return False


def real_looking_value(value: str) -> bool:
    """A value of an env var / config entry that could be a real secret (unknown format)."""
    v = value.strip()
    if len(v) < 16 or " " in v:
        return False
    if v.startswith(("$", "%", "<", "{")) or v.lower() in ("true", "false", "null", "undefined"):
        return False
    if re.match(r"(?i)^https?://", v):
        return False
    return not looks_like_placeholder(v) and len(set(v)) >= 10 and entropy(v) >= 3.0


# ---------------------------------------------------------------- env var names
PUBLIC_VAR_RE = re.compile(r"\b(?:NEXT_PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC|REACT_APP|VITE|PUBLIC)_[A-Z0-9_]+\b")

# Provider words that make a *_KEY / *_TOKEN / *_SECRET name a secret.
_PROVIDER_WORDS: list[tuple[str, str]] = [
    (r"OPENAI|OPEN_AI|AZURE_OPENAI", "openai"),
    (r"ANTHROPIC|CLAUDE", "anthropic"),
    (r"GEMINI|GOOGLE_AI|GOOGLE_GENAI|GOOGLE_GENERATIVE_AI|GENAI|GENERATIVE_AI", "gemini"),
    (r"GROQ", "groq"),
    (r"MISTRAL", "mistral"),
    (r"OPENROUTER|OPEN_ROUTER", "openrouter"),
    (r"PERPLEXITY|PPLX", "perplexity"),
    (r"XAI|GROK", "xai"),
    (r"DEEPSEEK", "deepseek"),
    (r"TOGETHER", "together"),
    (r"COHERE", "cohere"),
    (r"REPLICATE", "replicate"),
    (r"HUGGING_?FACE|HF", "huggingface"),
    (r"ELEVEN_?LABS", "elevenlabs"),
    (r"FIREWORKS|LANGSMITH|LANGCHAIN|PINECONE|VOYAGE|TAVILY|SERPER|SERPAPI|DEEPGRAM|ASSEMBLYAI|STABILITY", "generic"),
    (r"SENDGRID", "sendgrid"),
    (r"RESEND", "resend"),
    (r"POSTMARK|MAILGUN|BREVO|MAILCHIMP", "generic"),
    (r"GITHUB|GH", "github"),
    (r"SLACK", "slack"),
    (r"STRIPE", "stripe"),
    (r"RAZORPAY", "razorpay"),
    (r"SUPABASE", "supabase"),
    (r"AWS", "aws"),
    (r"TWILIO", "twilio"),
]
# Names that are public by design even with KEY/TOKEN in them.
_PUBLIC_NAME = re.compile(
    r"PUBLISHABLE|ANON|PUBLIC_KEY|SITE_KEY|SITEKEY|CLIENT_ID|KEY_ID|MEASUREMENT_ID|PROJECT_ID|APP_ID|ACCOUNT_SID|"
    r"_URL$|_URI$|_ENDPOINT$|_MODEL|_REGION|_BUCKET|_DOMAIN|_HOST|_VERSION|_ORG|_ID$|"
    r"FIREBASE|MAPBOX|MAPS|ALGOLIA_SEARCH|SEARCH_KEY|SEARCH_ONLY|POSTHOG|SENTRY_DSN|AMPLITUDE|MIXPANEL|SEGMENT|"
    r"RECAPTCHA_SITE|TURNSTILE_SITE|VAPID_PUBLIC|CLERK_PUBLISHABLE|PADDLE_CLIENT"
)
_GENERIC_SECRET = re.compile(
    r"(?:^|_)(?:SECRET|SECRET_KEY|CLIENT_SECRET|KEY_SECRET|PRIVATE_KEY|SERVICE_ROLE(?:_KEY)?|SERVICE_KEY|"
    r"PASSWORD|PASSWD|DB_PASS|AUTH_TOKEN|ADMIN_KEY|ADMIN_TOKEN|MASTER_KEY|SIGNING_KEY|WEBHOOK_SECRET|JWT_SECRET)(?:_|$)"
)
_KEYISH = re.compile(r"(?:^|_)(?:API_?KEY|KEY|TOKEN|SECRET|PAT|ACCESS_KEY|SECRET_ACCESS_KEY|AUTH)(?:_|$)")
_DB_NAME = re.compile(r"(?:^|_)(?:DATABASE|DB|POSTGRES|POSTGRESQL|PG|MYSQL|MONGO|MONGODB|REDIS|NEON|TURSO)"
                      r"(?:_[A-Z]+)?_(?:URL|URI|CONNECTION|CONNECTION_STRING|DSN)$")
RE_DB_URL_PASSWORD = re.compile(r"^[a-z][a-z0-9+.\-]*://[^:/@\s]+:([^@\s]+)@([^/:?\s]+)", re.I)
LOCAL_HOSTS = {"localhost", "127.0.0.1", "0.0.0.0", "host.docker.internal", "db", "postgres", "mysql", "redis",
               "mongo", "[::1]"}
DEFAULT_PASSWORDS = {"postgres", "password", "pass", "root", "admin", "secret", "changeme", "example", "test",
                     "mysql", "mongo", "redis", "user", "prisma"}


def strip_public_prefix(name: str) -> tuple[str | None, str]:
    for p in PUBLIC_PREFIXES:
        if name.startswith(p):
            return p, name[len(p):]
    return None, name


def provider_for_name(name: str) -> str | None:
    for pat, prov in _PROVIDER_WORDS:
        if re.search(rf"(?:^|_)(?:{pat})(?:_|$)", name):
            return prov
    return None


def classify_secret_name(name: str) -> str | None:
    """Return the provider id if NAME (public prefix already stripped or not) names a secret,
    'database' for connection strings (value must still contain a password), else None."""
    _, bare = strip_public_prefix(name)
    if _DB_NAME.search(bare):
        return "database"
    if _PUBLIC_NAME.search(bare):
        # STRIPE_SECRET_KEY has no public marker; NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY does.
        return None
    if _GENERIC_SECRET.search(bare):
        return provider_for_name(bare) or ("supabase" if "SERVICE_ROLE" in bare else "generic")
    prov = provider_for_name(bare)
    if prov and _KEYISH.search(bare):
        if prov in ("stripe", "razorpay", "supabase", "twilio", "aws"):
            # These have public keys too (pk_, rzp_ key id, anon, account SID, access key id):
            # only the explicit secret names count (handled above) - or a secret value.
            return None
        return prov
    return None


def db_url_has_real_password(value: str) -> bool:
    m = RE_DB_URL_PASSWORD.match(value.strip())
    if not m:
        return False
    pw, host = m.group(1), m.group(2).lower()
    if host in LOCAL_HOSTS or pw.lower() in DEFAULT_PASSWORDS or pw.startswith(("$", "%", "<", "{")):
        return False
    return not PLACEHOLDER_WORDS.search(pw)


@dataclass
class ValueMatch:
    label: str
    provider: str
    value: str
    severity: str
    start: int


def find_tokens(text: str) -> list[ValueMatch]:
    """All known-format secrets in TEXT (placeholders removed, overlaps resolved)."""
    out: list[ValueMatch] = []
    taken: list[tuple[int, int]] = []

    def free(a: int, b: int) -> bool:
        return all(b <= x or a >= y for x, y in taken)

    for tp in TOKEN_PATTERNS:
        for m in tp.regex.finditer(text):
            if not free(m.start(), m.end()):
                continue
            v = m.group(0)
            if tp.label != "Private key" and looks_like_placeholder(v, tp.prefix):
                continue
            if tp.label == "Private key" and not _private_key_has_body(text, m.end()):
                continue
            taken.append((m.start(), m.end()))
            out.append(ValueMatch(tp.label, tp.provider, v, tp.severity, m.start()))
    for m in RE_JWT.finditer(text):
        role = secret_jwt_role(m.group(0))
        if role and free(m.start(), m.end()):
            taken.append((m.start(), m.end()))
            out.append(ValueMatch(f"Supabase {role} JWT", "supabase", m.group(0), "critical", m.start()))
    for m in RE_GOOGLE_KEY.finditer(text):
        ctx = text[max(0, m.start() - 300): m.end() + 300]
        if RE_GEMINI_CONTEXT.search(ctx) and not re.search(r"(?i)firebase|authDomain|maps", ctx) \
                and not looks_like_placeholder(m.group(0), re.compile("^AIza")) and free(m.start(), m.end()):
            taken.append((m.start(), m.end()))
            out.append(ValueMatch("Google Gemini API key", "gemini", m.group(0), "critical", m.start()))
    return sorted(out, key=lambda v: v.start)


def _private_key_has_body(text: str, end: int) -> bool:
    following = re.sub(r"\\n|\s", "", text[end: end + 200])
    return re.match(r"[A-Za-z0-9+/=]{64}", following) is not None


def classify_value(value: str) -> ValueMatch | None:
    """A single env/config value: known token format (incl. service_role JWT) or None."""
    found = find_tokens(value.strip())
    return found[0] if found else None


def is_publishable(value: str) -> bool:
    v = value.strip()
    if RE_PUBLISHABLE_VALUE.match(v):
        return True
    if RE_JWT.fullmatch(v):
        p = decode_jwt_payload(v)
        return bool(p) and str(p.get("role", "")) in ("anon", "authenticated")
    return False
