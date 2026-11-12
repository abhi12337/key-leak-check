"""Walks a project and runs every rule. Reads local files only: never runs, builds,
imports or connects to anything it scans. The only subprocess is a local `git`
(ls-files / check-ignore) to see whether .env files are committed or ignored."""

from __future__ import annotations

import bisect
import fnmatch
import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path

from .findings import Finding, mask_secret, redact_line, server_name
from .patterns import (
    PLACEHOLDER_WORDS,
    PUBLIC_VAR_RE,
    ValueMatch,
    classify_secret_name,
    classify_value,
    db_url_has_real_password,
    find_tokens,
    is_publishable,
    real_looking_value,
    strip_public_prefix,
)

MAX_BYTES_DEFAULT = 5 * 1024 * 1024
SKIP_DIRS = {"node_modules", ".git", ".hg", ".svn", ".venv", "venv", "__pycache__", "site-packages", ".tox",
             ".mypy_cache", ".pytest_cache", ".ruff_cache", "coverage", ".turbo", ".cache", ".parcel-cache",
             ".idea", ".vscode", ".expo", ".gradle", "Pods", "vendor", "bower_components", ".yarn", ".pnpm-store",
             ".angular", ".docusaurus", "storybook-static"}
ALLOWED_HIDDEN = {".github", ".next", ".output", ".svelte-kit", ".vercel"}
HIDDEN_BUILD = {".next": ["static"], ".output": ["public"], ".svelte-kit": ["output", "client"],
                ".vercel": ["output", "static"]}
BUILD_DIRS = {"dist", "build", "out", "web-build"}
TEST_DIRS = {"test", "tests", "__tests__", "spec", "specs", "fixtures", "__fixtures__", "testdata", "e2e",
             "__mocks__", "cypress", "playwright"}
CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".mts", ".cts", ".vue", ".svelte", ".astro"}
BUNDLE_EXT = {".js", ".mjs", ".cjs", ".html", ".htm"}
TEXT_EXT = CODE_EXT | {".json", ".jsonc", ".yml", ".yaml", ".toml", ".html", ".htm", ".md", ".mdx", ".txt",
                       ".py", ".sh", ".ps1", ".xml", ".plist", ".gradle", ".properties", ".swift", ".kt", ".java",
                       ".rb", ".go", ".php", ".cs", ".dart", ".ini", ".cfg", ".conf", ".sql", ".graphql", ".css"}
LOCKFILES = {"package-lock.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb", "bun.lock", "npm-shrinkwrap.json",
             "Cargo.lock", "poetry.lock", "Gemfile.lock", "composer.lock", "go.sum"}
ENV_TEMPLATE_SUFFIXES = (".example", ".sample", ".template", ".dist", ".defaults", ".tmpl", ".tpl")
NOT_ENV_FILES = {".xcode.env", ".envrc"}
IGNORE_MARK = re.compile(r"key-leak-check:\s*ignore", re.I)
CONFIG_NAME_RE = re.compile(
    r"^(?:(?:next|vite|nuxt|astro|svelte|remix|webpack|rsbuild|vitest)\.config\.[cm]?[jt]s|app\.json|app\.config\.[cm]?[jt]s|"
    r"eas\.json|vercel\.json|netlify\.toml|fly\.toml|render\.ya?ml|amplify\.ya?ml|wrangler\.toml|"
    r"(?:docker-)?compose(?:\.[\w-]+)?\.ya?ml|Dockerfile(?:\.[\w-]+)?|[\w.-]+\.Dockerfile)$"
)
FRAMEWORK_DEPS = [("next", "next"), ("nuxt", "nuxt"), ("@sveltejs/kit", "sveltekit"), ("astro", "astro"),
                  ("expo", "expo"),
                  # Full-stack frameworks on Vite that mix server and client code in one file: only
                  # "use client" / *.client.* files are known to be browser code.
                  ("@remix-run/dev", "ssr"), ("@react-router/dev", "ssr"), ("@tanstack/react-start", "ssr"),
                  ("@tanstack/start", "ssr"), ("@solidjs/start", "ssr"), ("@builder.io/qwik-city", "ssr"),
                  ("@analogjs/platform", "ssr"), ("vike", "ssr"), ("waku", "ssr"), ("@redwoodjs/core", "ssr"),
                  ("react-scripts", "cra"), ("vite", "vite")]
FRAMEWORK_FILES = [("next.config.", "next"), ("nuxt.config.", "nuxt"), ("svelte.config.", "sveltekit"),
                   ("astro.config.", "astro"), ("vite.config.", "vite")]

# ---------------------------------------------------------------- client / server
RE_USE_CLIENT = re.compile(r"""\A(?:\s|//[^\n]*\n|/\*.*?\*/)*['"]use client['"]""", re.S)
RE_SERVER_ONLY = re.compile(r"""\A(?:\s|//[^\n]*\n|/\*.*?\*/)*['"]use server['"]|^\s*import\s+['"]server-only['"]""",
                            re.S | re.M)
SERVER_SEGMENTS = {"api", "server", "servers", "backend", "functions", "netlify", "lambda", "lambdas", "worker",
                   "workers", "cron", "scripts", "supabase", "convex", "prisma", "edge-functions", "trpc", "migrations",
                   "seed", "db"}
RE_SERVER_FILE = re.compile(
    r"^(?:route\.[cm]?[jt]sx?|middleware\.[cm]?[jt]s|instrumentation\.[jt]s|server\.[cm]?[jt]s|"
    r"[^/]*\.server\.[cm]?[jt]sx?|\+server\.[jt]s|\+(?:page|layout)\.server\.[jt]s|hooks\.server\.[jt]s|"
    r"[^/]*\+api\.[jt]sx?|[^/]*\.config\.[cm]?[jt]s|gatsby-node\.[jt]s)$"
)
RE_NEXT_SERVER_DATA = re.compile(r"\b(?:getServerSideProps|getStaticProps|getStaticPaths)\b")

# ---------------------------------------------------------------- code patterns
RE_PROCESS_ENV = re.compile(r"\bprocess\.env(?:\.([A-Z][A-Z0-9_]*)|\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\])")
RE_IMPORT_META_ENV = re.compile(r"\bimport\.meta\.env(?:\.([A-Z][A-Z0-9_]*)|\[\s*['\"]([A-Z][A-Z0-9_]*)['\"]\s*\])")
RE_SVELTE_PUBLIC_IMPORT = re.compile(r"import\s*\{([^}]*)\}\s*from\s*['\"]\$env/static/public['\"]")
RE_SVELTE_DYNAMIC_PUBLIC = re.compile(r"from\s*['\"]\$env/dynamic/public['\"]")
RE_SVELTE_ENV_ACCESS = re.compile(r"\benv\.(PUBLIC_[A-Z0-9_]+)")
RE_NUXT_PUBLIC = re.compile(r"\.public\.([a-z][A-Za-z0-9]*)\b")
RE_DANGEROUS_BROWSER = re.compile(r"\bdangerouslyAllowBrowser\s*:\s*(?:true|!0)\b")
RE_SDK_NEW = re.compile(r"\bnew\s+(OpenAI|AzureOpenAI|Anthropic|AnthropicBedrock|Groq|Mistral|Together|Cerebras|"
                        r"Fireworks|OpenRouter|DeepSeek)\s*\(")
SDK_PROVIDER = {"OpenAI": "openai", "AzureOpenAI": "openai", "Anthropic": "anthropic", "AnthropicBedrock": "anthropic",
                "Groq": "groq", "Mistral": "mistral", "Together": "together", "OpenRouter": "openrouter",
                "DeepSeek": "deepseek"}
RE_GOOGLE_SDK = re.compile(r"\bnew\s+(GoogleGenerativeAI|GoogleGenAI)\s*\(")
RE_AI_SDK_FACTORY = re.compile(r"\b(createOpenAI|createAnthropic|createGoogleGenerativeAI|createGroq|createMistral|"
                               r"createXai|createDeepSeek|createOpenRouter)\s*\(\s*\{[^}]{0,300}?\bapiKey\b", re.S)
FACTORY_PROVIDER = {"createOpenAI": "openai", "createAnthropic": "anthropic", "createGoogleGenerativeAI": "gemini",
                    "createGroq": "groq", "createMistral": "mistral", "createXai": "xai", "createDeepSeek": "deepseek",
                    "createOpenRouter": "openrouter"}
AI_HOSTS = [
    (r"api\.openai\.com", "openai"), (r"api\.anthropic\.com", "anthropic"),
    (r"generativelanguage\.googleapis\.com", "gemini"), (r"api\.groq\.com", "groq"), (r"api\.mistral\.ai", "mistral"),
    (r"openrouter\.ai/api", "openrouter"), (r"api\.perplexity\.ai", "perplexity"), (r"api\.x\.ai", "xai"),
    (r"api\.deepseek\.com", "deepseek"), (r"api\.together\.(?:xyz|ai)", "together"), (r"api\.cohere\.(?:ai|com)", "cohere"),
    (r"api\.replicate\.com", "replicate"), (r"api\.elevenlabs\.io", "elevenlabs"),
]
RE_AI_HOST = re.compile(r"https?://(" + "|".join(h for h, _ in AI_HOSTS) + r")")
RE_AUTH_HEADER = re.compile(r"""(?i)['"]?(?:authorization|x-api-key|x-goog-api-key|xi-api-key|api-key)['"]?\s*:|"""
                            r"""Bearer\s|[?&]key=""")
RE_COMMENT_LINE = re.compile(r"^\s*(?://|\*|/\*|#|<!--)")


@dataclass
class ScanResult:
    root: str
    findings: list[Finding] = field(default_factory=list)
    files_scanned: int = 0
    env_files: list[str] = field(default_factory=list)
    source_files: int = 0
    build_files: int = 0
    build_dirs: list[str] = field(default_factory=list)
    frameworks: list[str] = field(default_factory=list)


# ---------------------------------------------------------------- small helpers
class _Lines:
    def __init__(self, text: str):
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]

    def line_of(self, pos: int) -> int:
        return bisect.bisect_right(self.starts, pos)

    def line_text(self, lineno: int) -> str:
        s = self.starts[lineno - 1]
        e = self.starts[lineno] - 1 if lineno < len(self.starts) else len(self.text)
        return self.text[s:e]


def _read(p: Path, max_bytes: int) -> str | None:
    try:
        if p.stat().st_size > max_bytes:
            return None
        data = p.read_bytes()
    except OSError:
        return None
    if b"\x00" in data[:8192]:
        return None
    return data.decode("utf-8", errors="replace")


def is_env_file(name: str) -> bool:
    if name in NOT_ENV_FILES:
        return False
    return name == ".env" or name.startswith(".env.") or name.endswith(".env")


def is_env_template(name: str) -> bool:
    return name.lower().endswith(ENV_TEMPLATE_SUFFIXES)


def _is_test_file(name: str) -> bool:
    n = name.lower()
    return bool(re.search(r"\.(?:test|spec|stories|story)\.[cm]?[jt]sx?$", n)) or n.startswith("test_")


def _camel_to_env(name: str) -> str:
    return re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", name).upper()


def _build_root(parts: list[str]) -> str | None:
    """Return the build-output root (as a rel path) that PARTS (a dir path) lies in, if any."""
    for i, p in enumerate(parts):
        if p in BUILD_DIRS:
            return "/".join(parts[: i + 1])
        if p in HIDDEN_BUILD:
            need = HIDDEN_BUILD[p]
            if parts[i + 1: i + 1 + len(need)] == need:
                return "/".join(parts[: i + 1 + len(need)])
            return None
    return None


def _keep_dir(parts: list[str], include_build: bool, include_tests: bool) -> bool:
    name = parts[-1]
    if name in SKIP_DIRS:
        return False
    if name.startswith(".") and name not in ALLOWED_HIDDEN:
        return False
    if not include_tests and name.lower() in TEST_DIRS:
        return False
    for i, p in enumerate(parts):          # hidden build dirs: only their client-output subtree
        if p in HIDDEN_BUILD:
            if not include_build:
                return False
            need = HIDDEN_BUILD[p]
            got = parts[i + 1: i + 1 + len(need)]
            if got != need[: len(got)]:
                return False
    root = _build_root(parts)
    if root is not None:
        if not include_build:
            return False
        inner = parts[len(root.split("/")):]
        if inner and inner[0] in ("server", "ssr", "functions"):
            return False                   # dist/server, build/server: server bundles, never sent to browsers
    return True


# ---------------------------------------------------------------- git / .gitignore
def _git(root: Path, *args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return None


def _git_env_status(root: Path, rels: list[str]) -> tuple[bool, set[str], set[str]]:
    """(is_git_repo, tracked, ignored) for the given env file paths."""
    if not rels:
        return False, set(), set()
    cp = _git(root, "rev-parse", "--is-inside-work-tree")
    if cp is None or cp.returncode != 0 or cp.stdout.strip() != "true":
        return False, set(), set()
    tracked: set[str] = set()
    ignored: set[str] = set()
    cp = _git(root, "ls-files", "--", *rels)
    if cp and cp.returncode == 0:
        tracked = {ln.strip() for ln in cp.stdout.splitlines() if ln.strip()}
    cp = _git(root, "check-ignore", "--", *rels)
    if cp and cp.returncode in (0, 1):
        ignored = {ln.strip() for ln in cp.stdout.splitlines() if ln.strip()}
    return True, tracked, ignored


def _gitignore_covers(root: Path, rel: str) -> bool:
    """Approximate .gitignore matching (for folders that are not git repos): every
    .gitignore from ROOT down to the file's folder, last match wins."""
    parts = rel.split("/")
    covered = False
    for depth in range(len(parts)):
        base = "/".join(parts[:depth])
        gi = root / base / ".gitignore" if base else root / ".gitignore"
        if not gi.is_file():
            continue
        sub = "/".join(parts[depth:])
        name = parts[-1]
        try:
            lines = gi.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue
        for raw in lines:
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            neg = line.startswith("!")
            pat = (line[1:] if neg else line).rstrip("/")
            anchored = pat.startswith("/") or "/" in pat
            pat = pat.lstrip("/")
            hit = fnmatch.fnmatch(sub, pat) or fnmatch.fnmatch(sub, pat + "/*") if anchored else \
                fnmatch.fnmatch(name, pat) or any(fnmatch.fnmatch(p, pat) for p in parts[depth:-1])
            if hit:
                covered = not neg
    return covered


# ---------------------------------------------------------------- the scanner
class Scanner:
    def __init__(self, root: Path, *, excludes: list[str], include_tests: bool, include_build: bool, max_bytes: int):
        self.root = root
        self.excludes = excludes
        self.include_tests = include_tests
        self.include_build = include_build
        self.max_bytes = max_bytes
        self.res = ScanResult(str(root.resolve()))
        self._fw_cache: dict[str, str | None] = {}
        self._reported_lines: set[tuple[str, int]] = set()
        self._seen: set[tuple] = set()

    # ------------------------------------------------------------ framework detection
    def framework_for(self, rel_dir: str) -> str | None:
        """Framework of the nearest enclosing package (package.json deps or config file)."""
        if rel_dir in self._fw_cache:
            return self._fw_cache[rel_dir]
        d = self.root / rel_dir if rel_dir else self.root
        fw = None
        pj = d / "package.json"
        if pj.is_file():
            try:
                data = json.loads(pj.read_text(encoding="utf-8", errors="replace"))
                deps = {**(data.get("dependencies") or {}), **(data.get("devDependencies") or {})}
            except (ValueError, OSError, AttributeError):
                deps = {}
            for dep, name in FRAMEWORK_DEPS:
                if dep in deps:
                    fw = name
                    break
        if fw is None:
            try:
                names = os.listdir(d)
            except OSError:
                names = []
            for prefix, name in FRAMEWORK_FILES:
                if any(n.startswith(prefix) for n in names):
                    fw = name
                    break
        if fw is None and not pj.is_file() and rel_dir:
            parent = rel_dir.rsplit("/", 1)[0] if "/" in rel_dir else ""
            fw = self.framework_for(parent)
            self._fw_cache[rel_dir] = fw
            return fw
        self._fw_cache[rel_dir] = fw
        if fw and fw != "ssr" and fw not in self.res.frameworks:
            self.res.frameworks.append(fw)
        return fw

    def _project_dir(self, rel: str) -> str:
        """Nearest ancestor folder (rel) holding a package.json, or the root."""
        parts = rel.split("/")[:-1]
        while parts:
            if (self.root / "/".join(parts) / "package.json").is_file():
                return "/".join(parts)
            parts.pop()
        return ""

    def classify(self, rel: str, text: str, fw: str | None) -> str:
        """'client', 'server' or 'unknown' for a code file."""
        proj = self._project_dir(rel)
        inner = rel[len(proj) + 1:] if proj else rel
        parts = inner.split("/")
        name = parts[-1]
        dirs = [p.lower() for p in parts[:-1]]
        head = text[:3000]
        if RE_USE_CLIENT.search(head) or re.search(r"\.client\.[cm]?[jt]sx?$", name):
            return "client"
        if RE_SERVER_ONLY.search(head) or RE_SERVER_FILE.match(name) or any(d in SERVER_SEGMENTS for d in dirs):
            return "server"
        if dirs and dirs[0] == "public":
            return "client"                # served as-is
        ext = os.path.splitext(name)[1].lower()
        if ext in (".svelte", ".vue"):
            return "client"
        if fw in ("vite", "cra", "expo"):
            return "client"
        if fw == "next":
            if dirs[:1] == ["pages"] or dirs[:2] == ["src", "pages"]:
                return "unknown" if RE_NEXT_SERVER_DATA.search(text) else "client"
            if "hooks" in dirs:
                return "client"
        if fw == "sveltekit" and re.match(r"^\+(?:page|layout)\.[jt]s$", name):
            return "client"
        if fw == "nuxt" and dirs and dirs[0 if dirs[0] != "app" else min(1, len(dirs) - 1)] in (
                "components", "pages", "composables", "layouts", "plugins", "middleware", "stores", "utils"):
            return "client"
        return "unknown"

    # ------------------------------------------------------------ reporting
    def add(self, rule: str, sev: str, msg: str, rel: str, line: int | None, evidence: str | None = None,
            dedupe: tuple | None = None, **extra) -> None:
        key = dedupe if dedupe is not None else (rule, rel, line)
        if key in self._seen:
            return
        self._seen.add(key)
        self.res.findings.append(Finding(rule, sev, msg, rel, line, evidence,
                                         extra={k: v for k, v in extra.items() if v is not None}))
        if line:
            self._reported_lines.add((rel, line))

    # ------------------------------------------------------------ walk
    def run(self) -> ScanResult:
        env_files: list[tuple[Path, str]] = []
        code_files: list[tuple[Path, str]] = []
        build_files: dict[str, list[tuple[Path, str]]] = {}
        maps: dict[str, list[str]] = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = Path(dirpath).relative_to(self.root).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir
            dparts = rel_dir.split("/") if rel_dir else []
            keep = []
            for d in sorted(dirnames):
                rel = f"{rel_dir}/{d}" if rel_dir else d
                if not _keep_dir(dparts + [d], self.include_build, self.include_tests):
                    continue
                if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(rel + "/", g) for g in self.excludes):
                    continue
                keep.append(d)
            dirnames[:] = keep
            broot = _build_root(dparts) if dparts else None
            for fn in sorted(filenames):
                rel = f"{rel_dir}/{fn}" if rel_dir else fn
                if any(fnmatch.fnmatch(rel, g) or fnmatch.fnmatch(fn, g) for g in self.excludes):
                    continue
                p = Path(dirpath) / fn
                low = fn.lower()
                if broot is not None:
                    if low.endswith(".map"):
                        maps.setdefault(broot, []).append(rel)
                    elif os.path.splitext(low)[1] in BUNDLE_EXT:
                        build_files.setdefault(broot, []).append((p, rel))
                    continue
                if is_env_file(fn):
                    env_files.append((p, rel))
                    continue
                if fn in LOCKFILES or low.endswith((".map", ".min.css", ".d.ts")):
                    continue
                if not self.include_tests and _is_test_file(fn):
                    continue
                ext = os.path.splitext(low)[1]
                if ext in TEXT_EXT or CONFIG_NAME_RE.match(fn):
                    code_files.append((p, rel))

        self.scan_env_files(env_files)
        for p, rel in code_files:
            text = _read(p, self.max_bytes)
            if text is None:
                continue
            self.res.files_scanned += 1
            self.res.source_files += 1
            self.scan_source(rel, text)
        for broot in sorted(set(build_files) | set(maps)):
            self.res.build_dirs.append(broot)
            for p, rel in build_files.get(broot, []):
                text = _read(p, max(self.max_bytes, 20 * 1024 * 1024))
                if text is None:
                    continue
                self.res.files_scanned += 1
                self.res.build_files += 1
                self.scan_bundle(rel, text, broot)
            if maps.get(broot):
                self.report_maps(broot, maps[broot])
        return self.res

    # ------------------------------------------------------------ rule 1, 6: env files
    @staticmethod
    def parse_env(text: str) -> list[tuple[str, str, int, str]]:
        out = []
        for i, raw in enumerate(text.splitlines(), 1):
            line = raw.strip()
            if not line or line.startswith("#"):
                continue
            m = re.match(r"^(?:export\s+)?([A-Za-z_][A-Za-z0-9_.]*)\s*=\s*(.*)$", line)
            if not m:
                continue
            name, val = m.group(1), m.group(2).strip()
            if val[:1] in ("'", '"'):
                q = val[0]
                end = val.find(q, 1)
                val = val[1:end] if end > 0 else val[1:]
            else:
                val = re.split(r"\s+#", val, maxsplit=1)[0].strip()
            out.append((name, val, i, raw))
        return out

    def _secret_in_value(self, name: str, val: str) -> tuple[str, str, str] | None:
        """(label, provider, secret value) if VAL is a secret for var NAME, else None."""
        if not val:
            return None
        if is_publishable(val):
            # Google keys (AIza...) are public as Firebase web keys, secret as Gemini keys.
            if not (val.startswith("AIza") and classify_secret_name(name) == "gemini" and real_looking_value(val)):
                return None
            return "Google Gemini API key", "gemini", val
        tok = classify_value(val)
        if tok:
            return tok.label, tok.provider, tok.value
        prov = classify_secret_name(name)
        if prov == "database":
            return ("Database URL with password", "database", val) if db_url_has_real_password(val) else None
        if prov and real_looking_value(val):
            return f"{_pretty(prov)} secret", prov, val
        return None

    def scan_env_files(self, env_files: list[tuple[Path, str]]) -> None:
        real = [rel for _, rel in env_files if not is_env_template(rel.rsplit("/", 1)[-1])]
        is_git, tracked, ignored = _git_env_status(self.root, real)
        for p, rel in env_files:
            text = _read(p, self.max_bytes)
            if text is None:
                continue
            self.res.files_scanned += 1
            self.res.env_files.append(rel)
            template = is_env_template(rel.rsplit("/", 1)[-1])
            fw = self.framework_for(rel.rsplit("/", 1)[0] if "/" in rel else "")
            secrets_here: list[tuple[str, int]] = []
            for name, val, ln, raw in self.parse_env(text):
                if IGNORE_MARK.search(raw):
                    continue
                hit = self._secret_in_value(name, val)
                prefix, _ = strip_public_prefix(name)
                ev = redact_line(raw, [val] if hit or real_looking_value(val) else None)
                if hit:
                    secrets_here.append((name, ln))
                if prefix:
                    self._public_env_var(rel, ln, name, val, hit, template, fw, ev)
                if template and hit:
                    label, prov, value = hit
                    self.add("KLC008", "medium",
                             f"{name} in {rel} holds a value that looks like a real {label}. Example files are "
                             f"committed and copied by everyone who clones the repo.",
                             rel, ln, ev, var=name, provider=prov, framework=fw)
            if template or not secrets_here:
                continue
            names = ", ".join(n for n, _ in secrets_here[:4]) + (" ..." if len(secrets_here) > 4 else "")
            if is_git:
                if rel in tracked:
                    self.add("KLC007", "high", f"{rel} is tracked by git and holds secrets ({names}): they are in "
                             "every clone and in the history.", rel, None, None, var=secrets_here[0][0])
                elif rel not in ignored:
                    self.add("KLC007", "high", f"{rel} holds secrets ({names}) and is not git-ignored: one "
                             "`git add .` away from being committed.", rel, None, None, var=secrets_here[0][0])
            elif not _gitignore_covers(self.root, rel):
                self.add("KLC007", "high", f"{rel} holds secrets ({names}) and no .gitignore covers it.",
                         rel, None, None, var=secrets_here[0][0])

    def _public_env_var(self, rel: str, ln: int, name: str, val: str, hit, template: bool, fw: str | None,
                        ev: str) -> None:
        sname = server_name(name)
        if hit:
            label, prov, _ = hit
            if template:
                self.add("KLC001", "high",
                         f"{name} is a browser-exposed variable (public prefix) and this template gives it a "
                         f"{label}: everyone who copies it ships the key to the browser.",
                         rel, ln, ev, var=name, server_var=sname, provider=prov, framework=fw)
            else:
                self.add("KLC001", "critical",
                         f"{label} in {name}: the public prefix makes the bundler inline it into the JavaScript "
                         f"every visitor downloads.",
                         rel, ln, ev, var=name, server_var=sname, provider=prov, framework=fw)
            return
        prov = classify_secret_name(name)
        if not prov or prov == "database":
            return
        empty_or_placeholder = (not val) or bool(PLACEHOLDER_WORDS.search(val))
        explicit = bool(re.search(r"SECRET|SERVICE_ROLE|PRIVATE_KEY", name))
        from .findings import PROVIDERS
        if empty_or_placeholder and (explicit or PROVIDERS.get(prov, PROVIDERS["generic"]).kind == "ai"):
            where = "this template tells everyone to put" if template else "it is set up to hold"
            self.add("KLC001", "high",
                     f"{name} names a secret ({_pretty(prov)}) but has a public prefix: {where} the key in a "
                     f"variable the bundler ships to the browser.",
                     rel, ln, ev, var=name, server_var=sname, provider=prov, framework=fw)

    # ------------------------------------------------------------ source files
    def scan_source(self, rel: str, text: str) -> None:
        name = rel.rsplit("/", 1)[-1]
        rel_dir = rel.rsplit("/", 1)[0] if "/" in rel else ""
        fw = self.framework_for(rel_dir)
        ext = os.path.splitext(name)[1].lower()
        lines = _Lines(text)
        is_code = ext in CODE_EXT
        kind = self.classify(rel, text, fw) if is_code else ("client" if rel.split("/")[0] == "public" or
                                                             ext in (".html", ".htm") else "unknown")
        if CONFIG_NAME_RE.match(name) or re.search(r"(?:^|/)\.github/workflows/[^/]+\.ya?ml$", rel):
            self.scan_config(rel, text, lines, fw)
        if is_code:
            self.scan_env_reads(rel, text, lines, fw, kind)
            if kind != "server":
                self.scan_ai_browser(rel, text, lines, fw, kind)
        self.scan_tokens(rel, text, lines, fw, kind)

    def _ignored(self, lines: _Lines, ln: int) -> bool:
        return bool(IGNORE_MARK.search(lines.line_text(ln)))

    # rule 1 (config files) + KLC002 build-config inlining
    def scan_config(self, rel: str, text: str, lines: _Lines, fw: str | None) -> None:
        for m in re.finditer(r"""\b((?:NEXT_PUBLIC|NUXT_PUBLIC|EXPO_PUBLIC|REACT_APP|VITE|PUBLIC)_[A-Z0-9_]+)\b['"]?"""
                             r"""(?:\s*[:=]\s*|[ \t]+)['"]?([^\s'"#,}\]]+)""", text):
            name, val = m.group(1), m.group(2)
            if val.startswith(("$", "process.", "import.", "env.", "{", "(")) or val in ("=", ":"):
                continue
            ln = lines.line_of(m.start())
            if self._ignored(lines, ln):
                continue
            hit = self._secret_in_value(name, val)
            if hit:
                self._public_env_var(rel, ln, name, val, hit, False, fw, redact_line(lines.line_text(ln), [val]))
        base = rel.rsplit("/", 1)[-1]
        blocks: list[tuple[str, str]] = []
        if base.startswith("vite.config.") or base.startswith(("astro.config.", "svelte.config.", "nuxt.config.")):
            blocks.append(("define", "vite.config `define`"))
        if base.startswith("next.config."):
            blocks.append(("env", "next.config `env`"))
        if base.startswith(("app.config.", "app.json")):
            blocks.append(("extra", "Expo `extra` (bundled into the app)"))
        if base.startswith("nuxt.config."):
            blocks.append(("public", "Nuxt runtimeConfig.public"))
        for key, label in blocks:
            for bm in re.finditer(rf"""['"]?\b{key}\b['"]?\s*:\s*\{{""", text):
                body_start = bm.end()
                body = _brace_body(text, body_start - 1)
                for km in re.finditer(r"""(?:^|[{,\s])['"]?([A-Za-z_$][\w$.]*)['"]?\s*:""", body):
                    raw_key = km.group(1)
                    var = raw_key.split(".")[-1]
                    if not re.fullmatch(r"[A-Z0-9_]+", var):
                        var = _camel_to_env(var)
                    prov = classify_secret_name(var)
                    if not prov:
                        # "process.env.API_KEY": JSON.stringify(env.GEMINI_API_KEY) - the value names it
                        rest = re.split(r"[,\n]", body[km.end():], maxsplit=1)[0]
                        for vm in re.finditer(r"\b[A-Z][A-Z0-9_]{3,}\b", rest):
                            if classify_secret_name(vm.group(0)):
                                prov = classify_secret_name(vm.group(0))
                                var = vm.group(0)
                                break
                    if not prov:
                        continue
                    pos = body_start + km.start(1)
                    ln = lines.line_of(pos)
                    if self._ignored(lines, ln):
                        continue
                    self.add("KLC002", "critical",
                             f"{raw_key} is inlined into the client bundle by {label}: the secret value ships "
                             f"to every visitor even though it has no public prefix.",
                             rel, ln, redact_line(lines.line_text(ln)), var=raw_key,
                             server_var=server_name(var), provider=prov, framework=fw, via=label)

    # rule 2
    def scan_env_reads(self, rel: str, text: str, lines: _Lines, fw: str | None, kind: str) -> None:
        refs: list[tuple[str, int, str]] = []    # (var, pos, how)
        for m in RE_PROCESS_ENV.finditer(text):
            var = m.group(1) or m.group(2)
            if var.startswith(("NEXT_PUBLIC_", "EXPO_PUBLIC_", "REACT_APP_", "NUXT_PUBLIC_")):
                refs.append((var, m.start(), "process.env"))
        for m in RE_IMPORT_META_ENV.finditer(text):
            var = m.group(1) or m.group(2)
            if var.startswith(("VITE_", "PUBLIC_", "NEXT_PUBLIC_", "REACT_APP_")):
                refs.append((var, m.start(), "import.meta.env"))
        for m in RE_SVELTE_PUBLIC_IMPORT.finditer(text):
            for nm in re.finditer(r"\b(PUBLIC_[A-Z0-9_]+)\b", m.group(1)):
                refs.append((nm.group(1), m.start() + 1 + m.group(0).find(nm.group(1)), "$env/static/public"))
        if RE_SVELTE_DYNAMIC_PUBLIC.search(text):
            for m in RE_SVELTE_ENV_ACCESS.finditer(text):
                refs.append((m.group(1), m.start(), "$env/dynamic/public"))
        if "useRuntimeConfig" in text:
            for m in RE_NUXT_PUBLIC.finditer(text):
                refs.append(("NUXT_PUBLIC_" + _camel_to_env(m.group(1)), m.start(), "runtimeConfig.public"))
        for var, pos, how in refs:
            prov = classify_secret_name(var)
            if not prov:
                continue
            ln = lines.line_of(pos)
            line = lines.line_text(ln)
            if RE_COMMENT_LINE.match(line) or self._ignored(lines, ln):
                continue
            shown = var if how != "runtimeConfig.public" else f"runtimeConfig.public.{_nuxt_key(var)}"
            if kind == "server":
                sev, msg = "medium", (f"{shown} names a secret but has a public prefix. This file is server-only, "
                                      f"so it is not shipped from here, but any client file that reads it will "
                                      f"inline it. Rename it.")
            else:
                where = "browser code" if kind == "client" else "code that can run in the browser"
                sev, msg = "critical", (f"{how} reads {shown} in {where}: the bundler replaces it with the secret "
                                        f"value in the JavaScript every visitor downloads.")
            self.add("KLC002", sev, msg, rel, ln, redact_line(line), dedupe=("KLC002", rel, var),
                     var=var, server_var=server_name(var), provider=prov, framework=fw)

    # rule 3
    def scan_ai_browser(self, rel: str, text: str, lines: _Lines, fw: str | None, kind: str) -> None:
        for m in RE_DANGEROUS_BROWSER.finditer(text):
            ln = lines.line_of(m.start())
            if RE_COMMENT_LINE.match(lines.line_text(ln)) or self._ignored(lines, ln):
                continue
            sdk = None
            for sm in RE_SDK_NEW.finditer(text, max(0, m.start() - 1500), m.start()):
                sdk = sm.group(1)
            prov = SDK_PROVIDER.get(sdk or "", "openai")
            label = f"new {sdk}(...)" if sdk else "An AI SDK client"
            self.add("KLC003", "high",
                     f"{label} is created with dangerouslyAllowBrowser: true, so it runs in the browser with "
                     f"your API key.", rel, ln, redact_line(lines.line_text(ln)),
                     var=_guess_var(text, prov), provider=prov, framework=fw)
        if kind != "client":
            return
        for m in RE_GOOGLE_SDK.finditer(text):
            ln = lines.line_of(m.start())
            if RE_COMMENT_LINE.match(lines.line_text(ln)) or self._ignored(lines, ln):
                continue
            self.add("KLC003", "high",
                     f"new {m.group(1)}(...) in browser code: the Gemini API key it is given is readable by "
                     f"every visitor.", rel, ln, redact_line(lines.line_text(ln)),
                     var=_guess_var(text, "gemini"), provider="gemini", framework=fw)
        for m in RE_AI_SDK_FACTORY.finditer(text):
            ln = lines.line_of(m.start())
            if self._ignored(lines, ln):
                continue
            prov = FACTORY_PROVIDER[m.group(1)]
            self.add("KLC003", "high", f"{m.group(1)}({{ apiKey }}) in browser code: the key is shipped to every "
                     f"visitor.", rel, ln, redact_line(lines.line_text(ln)),
                     var=_guess_var(text, prov), provider=prov, framework=fw)
        if not RE_AUTH_HEADER.search(text):
            return
        for m in RE_AI_HOST.finditer(text):
            ln = lines.line_of(m.start())
            if RE_COMMENT_LINE.match(lines.line_text(ln)) or self._ignored(lines, ln):
                continue
            host = m.group(1)
            prov = next(p for h, p in AI_HOSTS if re.fullmatch(h, host))
            self.add("KLC003", "high",
                     f"Browser code calls {host} directly with an API key header: the key is visible in every "
                     f"visitor's network tab.", rel, ln, redact_line(lines.line_text(ln)),
                     dedupe=("KLC003", rel, host), var=_guess_var(text, prov), provider=prov, framework=fw)

    # rule 4
    def scan_tokens(self, rel: str, text: str, lines: _Lines, fw: str | None, kind: str) -> None:
        for tok in find_tokens(text):
            ln = lines.line_of(tok.start)
            if (rel, ln) in self._reported_lines or self._ignored(lines, ln):
                continue
            sev = tok.severity
            if kind == "server" and sev == "critical":
                sev = "high"
            where = {"client": "browser code", "server": "server-side code"}.get(kind, "source code")
            self.add("KLC004", sev, f"{tok.label} hard-coded in {where}.", rel, ln,
                     redact_line(lines.line_text(ln), [tok.value]), dedupe=("KLC004", rel, tok.value),
                     var=_guess_var(text, tok.provider), provider=tok.provider, framework=fw)

    # rule 5
    def scan_bundle(self, rel: str, text: str, broot: str) -> None:
        lines = _Lines(text)
        fw = self.framework_for(broot.rsplit("/", 1)[0] if "/" in broot else "")
        for tok in find_tokens(text):
            self.add("KLC005", tok.severity, f"{tok.label} found in built file served to browsers ({broot}/).",
                     rel, lines.line_of(tok.start), mask_secret(tok.value), dedupe=("KLC005", rel, tok.value),
                     provider=tok.provider, framework=fw, var=_guess_var("", tok.provider))

    def report_maps(self, broot: str, maps: list[str]) -> None:
        n = len(maps)
        self.add("KLC006", "medium",
                 f"{n} source map file(s) in {broot}/ (e.g. {maps[0]}): anyone can rebuild your original source "
                 f"from the deployed site.", maps[0], None, None, dedupe=("KLC006", broot),
                 framework=self.framework_for(broot.rsplit("/", 1)[0] if "/" in broot else ""))


# ---------------------------------------------------------------- helpers
def _pretty(prov: str) -> str:
    from .findings import PROVIDERS
    p = PROVIDERS.get(prov)
    return p.name if p and prov != "generic" else "API"


def _nuxt_key(var: str) -> str:
    parts = var.replace("NUXT_PUBLIC_", "").lower().split("_")
    return parts[0] + "".join(x.capitalize() for x in parts[1:])


DEFAULT_ENV = {"openai": "OPENAI_API_KEY", "anthropic": "ANTHROPIC_API_KEY", "gemini": "GEMINI_API_KEY",
               "groq": "GROQ_API_KEY", "mistral": "MISTRAL_API_KEY", "openrouter": "OPENROUTER_API_KEY",
               "perplexity": "PERPLEXITY_API_KEY", "xai": "XAI_API_KEY", "deepseek": "DEEPSEEK_API_KEY",
               "together": "TOGETHER_API_KEY", "cohere": "COHERE_API_KEY", "replicate": "REPLICATE_API_TOKEN",
               "huggingface": "HF_TOKEN", "elevenlabs": "ELEVENLABS_API_KEY", "stripe": "STRIPE_SECRET_KEY",
               "razorpay": "RAZORPAY_KEY_SECRET", "supabase": "SUPABASE_SERVICE_ROLE_KEY",
               "aws": "AWS_SECRET_ACCESS_KEY", "sendgrid": "SENDGRID_API_KEY", "resend": "RESEND_API_KEY",
               "twilio": "TWILIO_AUTH_TOKEN", "github": "GITHUB_TOKEN", "slack": "SLACK_BOT_TOKEN",
               "database": "DATABASE_URL"}


def _guess_var(text: str, prov: str) -> str:
    """The env var name the code already uses for this provider, else the conventional one."""
    for m in PUBLIC_VAR_RE.finditer(text):
        if classify_secret_name(m.group(0)) == prov:
            return m.group(0)
    return DEFAULT_ENV.get(prov, "API_KEY")


def _brace_body(text: str, open_idx: int, limit: int = 6000) -> str:
    depth = 0
    for i in range(open_idx, min(len(text), open_idx + limit)):
        c = text[i]
        if c == "{":
            depth += 1
        elif c == "}":
            depth -= 1
            if depth == 0:
                return text[open_idx + 1: i]
    return text[open_idx + 1: open_idx + limit]


def scan_path(target: str, *, excludes: list[str] | None = None, include_tests: bool = False,
              include_build: bool = True, max_bytes: int = MAX_BYTES_DEFAULT) -> ScanResult:
    root = Path(target)
    if root.is_file():
        sc = Scanner(root.parent, excludes=[], include_tests=True, include_build=include_build, max_bytes=max_bytes)
        rel = root.name
        text = _read(root, max_bytes)
        if text is not None:
            if is_env_file(rel):
                sc.scan_env_files([(root, rel)])
            else:
                sc.res.files_scanned += 1
                sc.res.source_files += 1
                sc.scan_source(rel, text)
        for f in sc.res.findings:
            f.file = target.replace("\\", "/")
        return sc.res
    return Scanner(root, excludes=excludes or [], include_tests=include_tests, include_build=include_build,
                   max_bytes=max_bytes).run()


__all__ = ["ScanResult", "Scanner", "scan_path", "MAX_BYTES_DEFAULT", "ValueMatch"]
