"""Finding model and the rule catalogue (ids, severities, why it matters, how to fix)."""

from __future__ import annotations

import math
import re
import textwrap
from dataclasses import asdict, dataclass, field

SEVERITIES = ("critical", "high", "medium", "low", "info")
SEVERITY_RANK = {name: i for i, name in enumerate(SEVERITIES)}  # lower = worse
FRAMEWORKS = ("next", "vite", "cra", "expo", "sveltekit", "nuxt", "astro")


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    why: str
    fix: str


RULES: dict[str, Rule] = {}


def _rule(id: str, title: str, why: str, fix: str) -> None:
    RULES[id] = Rule(id, title, " ".join(why.split()), textwrap.dedent(fix).strip(chr(10)))


_rule(
    "KLC001",
    "Secret in a browser-exposed env var",
    """
Bundlers copy every variable with a public prefix (NEXT_PUBLIC_, VITE_, REACT_APP_,
EXPO_PUBLIC_, PUBLIC_, NUXT_PUBLIC_) into the JavaScript sent to every visitor. A secret
key there is public the moment you deploy: anyone can open DevTools, copy it and spend
your credits or read your data. Bots scan deployed bundles for exactly these keys.
""",
    """
1. Rotate the key now. Every build made with the old value contains it, and old
   deploys and CDN caches keep serving it.
   Where: <rotate>.
2. Rename it without the public prefix so the bundler never inlines it:
     <var>  ->  <server_var>
   Set <server_var> in .env.local (git-ignored) and in your host's environment settings.
3. Use it only in server code, and let the browser call your endpoint instead:
<proxy>
""",
)
_rule(
    "KLC002",
    "Client code reads a secret through a public env var",
    """
`process.env.NEXT_PUBLIC_*`, `import.meta.env.VITE_*`, `process.env.EXPO_PUBLIC_*`,
`$env/static/public` and Nuxt `runtimeConfig.public` are replaced with the literal value
at build time. Code that reads a secret this way ships the secret itself to the browser.
The same is true for values inlined by `define` in vite.config or `env` in next.config.
""",
    """
1. Rotate the key: past builds already contain it.
   Where: <rotate>.
2. <rename_step>
3. Move the call that needs it to server code and call that from the browser:
<proxy>
""",
)
_rule(
    "KLC003",
    "AI API called directly from the browser",
    """
An AI SDK created in browser code (`dangerouslyAllowBrowser: true`, `new GoogleGenAI(...)`
in a client component) or a fetch to api.openai.com / api.anthropic.com with an
Authorization header from client code needs the API key in the browser. Anyone can
read it from the network tab and use your account; you also cannot rate-limit or
authenticate who spends your tokens.
""",
    """
1. Remove the API key and the SDK client from browser code (drop
   `dangerouslyAllowBrowser`). If the key was ever deployed, rotate it.
   Where: <rotate>.
2. Keep the key in a server-only variable (<server_var>, no public prefix) and proxy the
   request through your own endpoint that checks the user and rate-limits:
<proxy>
""",
)
_rule(
    "KLC004",
    "API key hard-coded in source",
    """
A key written into source code is in git history forever and, in front-end code, in the
bundle every visitor downloads. Leaked AI and payment keys are found by scanners within
minutes and used to run up bills.
""",
    """
1. Rotate the key now; removing it from the code does not un-leak it.
   Where: <rotate>.
2. Delete it from the code and from git history (git filter-repo or BFG), then load it
   from a server-only environment variable: <server_var> (no NEXT_PUBLIC_ / VITE_ /
   REACT_APP_ / EXPO_PUBLIC_ / PUBLIC_ prefix).
3. If browser code needs the result, proxy it through your server:
<proxy>
""",
)
_rule(
    "KLC005",
    "API key inside built JavaScript bundle",
    """
Files in dist/, build/, out/, .next/static and similar folders are exactly what your
host serves to browsers. A key found here is downloadable by anyone who opens the site,
whatever the source code looks like now.
""",
    """
1. Rotate the key now, then redeploy and purge the CDN cache.
   Where: <rotate>.
2. Find how it got into the bundle: a public-prefixed env var (see KLC001/KLC002), a
   vite.config `define`, a next.config `env` entry, or a hard-coded string (KLC004).
3. Keep it server-side and proxy the request:
<proxy>
""",
)
_rule(
    "KLC006",
    "Source maps shipped with the build",
    """
`.map` files next to your bundles let anyone rebuild your original source code, comments
and file layout from the deployed site, including any secrets or internal URLs in it.
They also make it much easier to find weak spots in your client logic.
""",
    """
Do not deploy source maps (or upload them privately to your error tracker instead):
  Vite:        build: { sourcemap: false }        (or "hidden" + upload to Sentry, then delete)
  Next.js:     productionBrowserSourceMaps: false  (the default) in next.config
  CRA:         GENERATE_SOURCEMAP=false npm run build
  SvelteKit / Astro / Nuxt: set the Vite option build.sourcemap = false
Then rebuild and redeploy, and delete the .map files from the host.
""",
)
_rule(
    "KLC007",
    ".env file with secrets committed or not git-ignored",
    """
.env files hold the real keys. If git tracks the file, every clone, fork and CI log has
them, and deleting the file later does not remove it from history. If it is merely not
ignored, one `git add .` publishes it.
""",
    """
1. Ignore every real env file in .gitignore:
     .env
     .env*.local
     .env.*
     !.env.example
2. If it was committed:  git rm --cached <file>  and commit, then rotate every key in it,
   because the old values stay in history (or rewrite history with git filter-repo).
3. Keep only placeholder values in .env.example.
""",
)
_rule(
    "KLC008",
    "Real-looking key in an env example/template",
    """
.env.example / .env.sample / .env.template files are committed on purpose and copied by
everyone who clones the repo. A value here that looks like a real key is either a leaked
key or a shared one that will end up in other people's apps.
""",
    """
1. If the value is real, rotate it.
   Where: <rotate>.
2. Replace it with an obvious placeholder:
     <var>=your-key-here
3. Keep real values in .env.local (git-ignored) or your host's env settings.
""",
)


# ---------------------------------------------------------------- providers
@dataclass(frozen=True)
class Provider:
    name: str
    rotate: str
    kind: str = "api"          # "ai", "api", "db"
    upstream: str = ""
    auth: str = 'Authorization: `Bearer ${<env>}`'


PROVIDERS: dict[str, Provider] = {
    "openai": Provider("OpenAI", "platform.openai.com -> API keys -> revoke", "ai",
                       "https://api.openai.com/v1/chat/completions"),
    "anthropic": Provider("Anthropic", "console.anthropic.com -> API keys -> disable/delete", "ai",
                          "https://api.anthropic.com/v1/messages",
                          '"x-api-key": <env>!, "anthropic-version": "2023-06-01"'),
    "gemini": Provider("Google Gemini", "aistudio.google.com/apikey or Google Cloud console -> Credentials -> "
                       "delete the key", "ai",
                       "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent",
                       '"x-goog-api-key": <env>!'),
    "groq": Provider("Groq", "console.groq.com -> API Keys -> delete", "ai",
                     "https://api.groq.com/openai/v1/chat/completions"),
    "mistral": Provider("Mistral", "console.mistral.ai -> API keys -> delete", "ai",
                        "https://api.mistral.ai/v1/chat/completions"),
    "openrouter": Provider("OpenRouter", "openrouter.ai/settings/keys -> delete", "ai",
                           "https://openrouter.ai/api/v1/chat/completions"),
    "perplexity": Provider("Perplexity", "perplexity.ai/settings/api -> revoke", "ai",
                           "https://api.perplexity.ai/chat/completions"),
    "xai": Provider("xAI", "console.x.ai -> API keys -> delete", "ai", "https://api.x.ai/v1/chat/completions"),
    "deepseek": Provider("DeepSeek", "platform.deepseek.com -> API keys -> delete", "ai",
                         "https://api.deepseek.com/chat/completions"),
    "together": Provider("Together AI", "api.together.ai -> Settings -> API keys", "ai",
                         "https://api.together.xyz/v1/chat/completions"),
    "cohere": Provider("Cohere", "dashboard.cohere.com -> API keys -> delete", "ai", "https://api.cohere.com/v2/chat"),
    "replicate": Provider("Replicate", "replicate.com/account/api-tokens -> delete", "ai",
                          "https://api.replicate.com/v1/predictions"),
    "huggingface": Provider("Hugging Face", "huggingface.co/settings/tokens -> invalidate", "ai",
                            "https://router.huggingface.co/v1/chat/completions"),
    "elevenlabs": Provider("ElevenLabs", "elevenlabs.io -> Developers -> API keys -> delete", "ai",
                           "https://api.elevenlabs.io/v1/text-to-speech/<voice_id>", '"xi-api-key": <env>!'),
    "stripe": Provider("Stripe", "Stripe Dashboard -> Developers -> API keys -> Roll key"),
    "razorpay": Provider("Razorpay", "Razorpay Dashboard -> Account & Settings -> API Keys -> Regenerate"),
    "supabase": Provider("Supabase", "Supabase dashboard -> Project Settings -> API Keys (roll the JWT secret for "
                         "legacy keys, or delete the secret key and create a new one)"),
    "aws": Provider("AWS", "IAM -> Users -> Security credentials -> deactivate and delete the access key"),
    "sendgrid": Provider("SendGrid", "SendGrid -> Settings -> API Keys -> delete"),
    "resend": Provider("Resend", "resend.com/api-keys -> delete"),
    "twilio": Provider("Twilio", "Twilio Console -> Account -> API keys & tokens -> rotate the Auth Token"),
    "github": Provider("GitHub", "GitHub -> Settings -> Developer settings -> tokens -> revoke"),
    "slack": Provider("Slack", "api.slack.com/apps -> your app -> OAuth & Permissions -> revoke / rotate"),
    "database": Provider("database", "change the database user's password (and the connection string everywhere)",
                         "db"),
    "generic": Provider("provider", "the provider's dashboard"),
}


# ---------------------------------------------------------------- proxy snippets
def _proxy_ai(fw: str | None, env: str, prov: Provider) -> list[str]:
    auth = prov.auth.replace("<env>", _env_expr(fw, env))
    up = prov.upstream
    body = '{ /* model + validated prompt; never forward the raw body */ }'
    blocks: dict[str, list[str]] = {
        "next": [
            "Next.js, app/api/ai/route.ts (runs only on the server; a \"use server\" action also works):",
            "  export async function POST(req: Request) {",
            "    // check the user's session and rate-limit here: this endpoint spends your money",
            "    const { prompt } = await req.json();",
            f'    const r = await fetch("{up}", {{',
            '      method: "POST",',
            f'      headers: {{ "Content-Type": "application/json", {auth} }},',
            f"      body: JSON.stringify({body}),",
            "    });",
            "    return Response.json(await r.json(), { status: r.status });",
            "  }",
            '  browser:  await fetch("/api/ai", { method: "POST", body: JSON.stringify({ prompt }) })',
        ],
        "sveltekit": [
            "SvelteKit, src/routes/api/ai/+server.ts (server only):",
            f"  import {{ {env} }} from '$env/static/private';",
            "  export async function POST({ request, locals }) {",
            "    // check locals.user and rate-limit here",
            "    const { prompt } = await request.json();",
            f'    const r = await fetch("{up}", {{ method: "POST",',
            f'      headers: {{ "Content-Type": "application/json", {auth} }},',
            f"      body: JSON.stringify({body}) }});",
            "    return new Response(r.body, { status: r.status });",
            "  }",
        ],
        "nuxt": [
            "Nuxt, server/api/ai.post.ts (server only). In nuxt.config put the key in the private",
            f"runtimeConfig (top level, not under `public`), env name NUXT_{_snake_tail(env)}:",
            "  export default defineEventHandler(async (event) => {",
            "    // check the session and rate-limit here",
            "    const { prompt } = await readBody(event);",
            f"    const key = useRuntimeConfig(event).{_camel(env)};",
            f'    return await $fetch("{up}", {{ method: "POST",',
            f"      headers: {{ {prov.auth.replace('<env>', 'key').replace('key!', 'key')} }},",
            f"      body: {body} }});",
            "  });",
        ],
        "astro": [
            "Astro, src/pages/api/ai.ts (server endpoint; needs an SSR adapter or `export const prerender = false`):",
            "  export async function POST({ request }) {",
            "    const { prompt } = await request.json();     // check the session and rate-limit here",
            f'    const r = await fetch("{up}", {{ method: "POST",',
            f'      headers: {{ "Content-Type": "application/json", {auth} }},',
            f"      body: JSON.stringify({body}) }});",
            "    return new Response(r.body, { status: r.status });",
            "  }",
        ],
        "expo": [
            "Expo: the app bundle is on every phone, so the key must live on a server. With Expo Router",
            "API routes, app/api/ai+api.ts (deployed with EAS Hosting), or any small backend:",
            "  export async function POST(req: Request) {",
            "    const { prompt } = await req.json();     // check the user and rate-limit here",
            f'    const r = await fetch("{up}", {{ method: "POST",',
            f'      headers: {{ "Content-Type": "application/json", {auth} }},',
            f"      body: JSON.stringify({body}) }});",
            "    return Response.json(await r.json(), { status: r.status });",
            "  }",
        ],
        "vite": [
            "Vite / React (no server of its own): add a small backend, e.g. a Vercel/Netlify function",
            "api/ai.ts or an Express server, and proxy /api to it in dev (vite.config server.proxy):",
            '  app.post("/api/ai", async (req, res) => {',
            "    // check the user and rate-limit here: this endpoint spends your money",
            f'    const r = await fetch("{up}", {{ method: "POST",',
            f'      headers: {{ "Content-Type": "application/json", {auth} }},',
            f"      body: JSON.stringify({body}) }});",
            "    res.status(r.status).json(await r.json());",
            "  });",
            '  browser:  await fetch("/api/ai", { method: "POST", body: JSON.stringify({ prompt }) })',
        ],
    }
    blocks["cra"] = blocks["vite"]
    return _pick(blocks, fw)


def _proxy_generic(fw: str | None, env: str, prov: Provider) -> list[str]:
    what = ("query the database" if prov.kind == "db" else
            "call the provider's API" if prov.name == "provider" else f"call {prov.name}")
    blocks: dict[str, list[str]] = {
        "next": [f"Next.js: {what} in a route handler (app/api/.../route.ts), a \"use server\" action, or a",
                 f"module that starts with import \"server-only\"; read process.env.{env} there."],
        "sveltekit": [f"SvelteKit: {what} in +server.ts / +page.server.ts / src/lib/server/, using",
                      f"import {{ {env} }} from '$env/static/private'."],
        "nuxt": [f"Nuxt: {what} in server/api/*.ts and read the key from the private runtimeConfig",
                 f"(env NUXT_{_snake_tail(env)}), never from runtimeConfig.public."],
        "astro": [f"Astro: {what} in a server endpoint (src/pages/api/*.ts) or the frontmatter of an",
                  f"SSR page, using import.meta.env.{env} (no PUBLIC_ prefix)."],
        "expo": [f"Expo: {what} from your backend or an Expo Router API route (app/api/*+api.ts);",
                 "nothing in the app bundle is secret."],
        "vite": [f"Vite / React: {what} from a small backend (Vercel/Netlify function or Express) that",
                 f"reads process.env.{env}; the browser calls that endpoint."],
    }
    blocks["cra"] = blocks["vite"]
    return _pick(blocks, fw)


def _pick(blocks: dict[str, list[str]], fw: str | None) -> list[str]:
    if fw in blocks:
        return blocks[fw]
    return blocks["next"] + [""] + blocks["vite"]


def _env_expr(fw: str | None, env: str) -> str:
    if fw == "sveltekit":
        return env
    if fw == "astro":
        return f"import.meta.env.{env}"
    return f"process.env.{env}"


def _snake_tail(env: str) -> str:
    return re.sub(r"^NUXT_", "", env)


def _camel(env: str) -> str:
    parts = _snake_tail(env).lower().split("_")
    return parts[0] + "".join(p.capitalize() for p in parts[1:])


def proxy_snippet(fw: str | None, env: str, provider: str | None) -> str:
    prov = PROVIDERS.get(provider or "generic", PROVIDERS["generic"])
    if prov.kind == "ai":
        lines = _proxy_ai(fw, env, prov)
    else:
        lines = _proxy_generic(fw, env, prov)
    return textwrap.indent("\n".join(lines), "   ")


# ---------------------------------------------------------------- findings
@dataclass
class Finding:
    rule_id: str
    severity: str
    message: str
    file: str | None = None
    line: int | None = None
    evidence: str | None = None
    heuristic: bool = False
    extra: dict = field(default_factory=dict)

    @property
    def rule(self) -> Rule:
        return RULES[self.rule_id]

    @property
    def location(self) -> str:
        if self.file is None:
            return ""
        return f"{self.file}:{self.line}" if self.line else self.file

    @property
    def fix(self) -> str:
        """The rule's fix text with this finding's names and framework filled in."""
        e = self.extra
        provider = e.get("provider") or "generic"
        prov = PROVIDERS.get(provider, PROVIDERS["generic"])
        var = e.get("var") or "NEXT_PUBLIC_OPENAI_API_KEY"
        server_var = e.get("server_var") or server_name(var)
        text = self.rule.fix
        if "<proxy>" in text:
            text = text.replace("<proxy>", proxy_snippet(e.get("framework"), server_var, provider))
        if e.get("via"):
            rename = (f"Remove {var} from {e['via']}. Do not inline the key any other way: only\n"
                      f"   server code may read it, as {server_var}.")
        else:
            rename = (f"Rename it without the public prefix:  {var}  ->  {server_var}\n"
                      "   (and remove it from vite.config `define` / next.config `env` if it is listed there).")
        subs = {
            "<rename_step>": rename,
            "<rotate>": prov.rotate,
            "<server_var>": server_var,
            "<var>": var,
            "<file>": self.file or ".env",
        }
        for k, v in subs.items():
            text = text.replace(k, v)
        return text

    def to_dict(self) -> dict:
        d = asdict(self)
        d["title"] = self.rule.title
        d["why"] = self.rule.why
        d["fix"] = self.fix
        if not d["extra"]:
            d.pop("extra")
        return d


PUBLIC_PREFIXES = ("NEXT_PUBLIC_", "NUXT_PUBLIC_", "EXPO_PUBLIC_", "REACT_APP_", "VITE_", "PUBLIC_")


def server_name(var: str) -> str:
    """NEXT_PUBLIC_OPENAI_API_KEY -> OPENAI_API_KEY (the name it should have)."""
    for p in PUBLIC_PREFIXES:
        if var.startswith(p):
            rest = var[len(p):]
            return ("NUXT_" + rest) if p == "NUXT_PUBLIC_" else rest
    return var


def sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: (SEVERITY_RANK[f.severity], f.rule_id, f.file or "", f.line or 0))


# ---------------------------------------------------------------- redaction
def mask_secret(value: str) -> str:
    """At most the first 4 characters plus the length: never enough to use the key."""
    keep = min(4, len(value) // 4)
    return f"{value[:keep]}**** ({len(value)} chars)"


def entropy(s: str) -> float:
    if not s:
        return 0.0
    counts: dict[str, int] = {}
    for ch in s:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(s)
    return -sum(c / n * math.log2(c / n) for c in counts.values())


_RANDOMISH = re.compile(r"[A-Za-z0-9_\-+/=.]{20,}")
_URL_PASSWORD = re.compile(r"(://[^:/@\s\"']+:)([^@\s\"'/]+)(@)")


def _mask_randomish(m: re.Match) -> str:
    """Mask long mixed-case alphanumeric runs that look random (keys of unknown formats).
    Identifiers (NEXT_PUBLIC_OPENAI_API_KEY), file names and URLs do not qualify."""
    s = m.group(0)
    if (re.search(r"[A-Z]", s) and re.search(r"[a-z]", s) and len(re.findall(r"\d", s)) >= 3
            and entropy(s) >= 3.8):
        return mask_secret(s)
    return s


def redact_line(line: str, secrets: list[str] | None = None, limit: int = 160) -> str:
    """Strip a source/config line for display, masking anything that could be a secret:
    the known values, URL passwords and any long high-entropy token."""
    from .patterns import TOKEN_PATTERNS  # local import: patterns imports this module

    s = line.strip()
    for secret in sorted(secrets or [], key=len, reverse=True):
        if secret and len(secret) >= 4:
            s = s.replace(secret, mask_secret(secret))
    for tp in TOKEN_PATTERNS:
        s = tp.regex.sub(lambda m: m.group(0) if "****" in m.group(0) else mask_secret(m.group(0)), s)
    s = _URL_PASSWORD.sub(lambda m: m.group(1) + mask_secret(m.group(2)) + m.group(3), s)
    s = _RANDOMISH.sub(_mask_randomish, s)
    if len(s) > limit:
        s = s[: limit - 3] + "..."
    return s
