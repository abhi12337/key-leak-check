"""KLC002 (secret via public env var / build-config inlining), KLC003 (AI API from the
browser), KLC004 (hard-coded keys in source)."""

import pytest

from key_leak_check.scanner import scan_path

NEXT = {"package.json": {"dependencies": {"next": "15.0.0"}}}
VITE = {"package.json": {"devDependencies": {"vite": "7.0.0"}}}
EXPO = {"package.json": {"dependencies": {"expo": "54.0.0"}}}
SVELTE = {"package.json": {"devDependencies": {"@sveltejs/kit": "2.0.0", "vite": "7.0.0"}}}
NUXT = {"package.json": {"dependencies": {"nuxt": "4.0.0"}}}


def scan(root, **kw):
    return scan_path(str(root), **kw).findings


def only(findings, rule):
    return [f for f in findings if f.rule_id == rule]


def rules_lines(findings):
    return sorted((f.rule_id, f.file, f.line, f.severity) for f in findings)


# ---------------------------------------------------------------- fixtures
def test_next_vulnerable_fixture(copy_fixture):
    root = copy_fixture("next_vulnerable")
    assert rules_lines(scan(root)) == [
        ("KLC002", "app/chat/page.tsx", 5, "critical"),
        ("KLC002", "components/Summary.tsx", 7, "critical"),
        ("KLC002", "next.config.js", 4, "critical"),
        ("KLC003", "app/chat/page.tsx", 6, "high"),
        ("KLC003", "components/Summary.tsx", 4, "high"),
    ]


def test_vite_vulnerable_fixture(copy_fixture):
    root = copy_fixture("vite_vulnerable")
    assert rules_lines(scan(root)) == [
        ("KLC002", "src/ai.ts", 8, "critical"),
        ("KLC002", "vite.config.ts", 7, "critical"),
        ("KLC002", "vite.config.ts", 8, "critical"),
        ("KLC003", "src/ai.ts", 1, "high"),
    ]


@pytest.mark.parametrize("name", ["next_clean", "vite_clean"])
def test_clean_fixtures(copy_fixture, name):
    assert scan(copy_fixture(name)) == []


# ---------------------------------------------------------------- KLC002
@pytest.mark.parametrize("pkg,rel,code,var", [
    (NEXT, "app/page.tsx", '"use client";\nconst k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n',
     "NEXT_PUBLIC_OPENAI_API_KEY"),
    (NEXT, "pages/index.tsx", 'const k = process.env["NEXT_PUBLIC_GROQ_API_KEY"];\n', "NEXT_PUBLIC_GROQ_API_KEY"),
    (VITE, "src/main.ts", "const k = import.meta.env.VITE_ANTHROPIC_API_KEY;\n", "VITE_ANTHROPIC_API_KEY"),
    (VITE, "src/pay.ts", "const k = import.meta.env.VITE_RAZORPAY_KEY_SECRET;\n", "VITE_RAZORPAY_KEY_SECRET"),
    (EXPO, "app/(tabs)/index.tsx", "const k = process.env.EXPO_PUBLIC_OPENAI_API_KEY;\n", "EXPO_PUBLIC_OPENAI_API_KEY"),
    ({"package.json": {"dependencies": {"react-scripts": "5.0.1"}}}, "src/App.js",
     "const k = process.env.REACT_APP_OPENAI_API_KEY;\n", "REACT_APP_OPENAI_API_KEY"),
    (SVELTE, "src/routes/+page.svelte",
     "<script>\n  import { PUBLIC_OPENAI_API_KEY, PUBLIC_SITE_NAME } from '$env/static/public';\n</script>\n",
     "PUBLIC_OPENAI_API_KEY"),
    (SVELTE, "src/lib/ai.ts", "import { env } from '$env/dynamic/public';\nconst k = env.PUBLIC_GEMINI_API_KEY;\n",
     "PUBLIC_GEMINI_API_KEY"),
    (NUXT, "components/Chat.vue",
     "<script setup>\nconst config = useRuntimeConfig();\nconst key = config.public.openaiApiKey;\n</script>\n",
     "NUXT_PUBLIC_OPENAI_API_KEY"),
    ({"package.json": {"dependencies": {"astro": "5.0.0"}}}, "src/components/Chat.tsx",
     "const k = import.meta.env.PUBLIC_SUPABASE_SERVICE_ROLE_KEY;\n", "PUBLIC_SUPABASE_SERVICE_ROLE_KEY"),
])
def test_public_env_secret_read_in_client_code(make_repo, pkg, rel, code, var):
    root = make_repo({**pkg, rel: code})
    [f] = only(scan(root), "KLC002")
    assert f.severity == "critical" and f.file == rel and f.extra["var"] == var


def test_public_env_secret_in_server_file_is_medium(make_repo):
    root = make_repo({**NEXT, "app/api/chat/route.ts": "const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;\n",
                      "lib/server-ai.ts": 'import "server-only";\nconst k = process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY;\n'})
    found = only(scan(root), "KLC002")
    assert [(f.file, f.severity) for f in found] == [("app/api/chat/route.ts", "medium"), ("lib/server-ai.ts", "medium")]


def test_public_env_reported_once_per_file(make_repo):
    root = make_repo({**VITE, "src/a.ts": "a(import.meta.env.VITE_OPENAI_API_KEY);\nb(import.meta.env.VITE_OPENAI_API_KEY);\n"})
    assert len(only(scan(root), "KLC002")) == 1


@pytest.mark.parametrize("code", [
    "const u = process.env.NEXT_PUBLIC_SUPABASE_URL, k = process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY;",
    "loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);",
    "const m = process.env.NEXT_PUBLIC_OPENAI_MODEL;",
    "const f = { apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY };",
    "const r = process.env.NEXT_PUBLIC_RAZORPAY_KEY_ID;",
    "const k = process.env.OPENAI_API_KEY;",                     # not public: undefined in the browser
    "// const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY;",       # comment
    "const k = process.env.NEXT_PUBLIC_OPENAI_API_KEY; // key-leak-check: ignore",
])
def test_public_env_clean(make_repo, code):
    root = make_repo({**NEXT, "app/page.tsx": '"use client";\n' + code + "\n"})
    assert scan(root) == []


@pytest.mark.parametrize("rel,content,var", [
    ("next.config.ts", "export default { env: { ANTHROPIC_API_KEY: process.env.ANTHROPIC_API_KEY } };\n",
     "ANTHROPIC_API_KEY"),
    ("vite.config.js", "export default { define: { 'import.meta.env.OPENAI_KEY': JSON.stringify(process.env.OPENAI_KEY) } };\n",
     "import.meta.env.OPENAI_KEY"),
    ("vite.config.ts", "export default { define: { 'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY) } };\n",
     "process.env.API_KEY"),
    ("app.config.ts", "export default { expo: { extra: { openaiApiKey: process.env.OPENAI_API_KEY } } };\n",
     "openaiApiKey"),
    ("nuxt.config.ts", "export default defineNuxtConfig({ runtimeConfig: { public: { stripeSecretKey: '' } } });\n",
     "stripeSecretKey"),
])
def test_build_config_inlining(make_repo, rel, content, var):
    root = make_repo({rel: content})
    [f] = only(scan(root), "KLC002")
    assert f.severity == "critical" and f.extra["var"] == var and f.extra.get("via")
    assert "Remove " + var in f.fix


def test_build_config_safe_entries(make_repo):
    root = make_repo({
        "next.config.js": "module.exports = { env: { APP_VERSION: '1.0', NEXT_PUBLIC_SITE: 'x' } };\n",
        "vite.config.ts": "export default { define: { __APP_VERSION__: JSON.stringify(pkg.version) } };\n",
        "nuxt.config.ts": "export default defineNuxtConfig({ runtimeConfig: { openaiApiKey: '', "
                          "public: { siteUrl: '' } } });\n",
        "app.json": {"expo": {"extra": {"eas": {"projectId": "abc"}, "apiUrl": "https://api.example.com"}}},
    })
    assert scan(root) == []


# ---------------------------------------------------------------- KLC003
@pytest.mark.parametrize("sdk,prov", [("OpenAI", "openai"), ("Anthropic", "anthropic"), ("Groq", "groq")])
def test_dangerously_allow_browser(make_repo, sdk, prov):
    root = make_repo({**VITE, "src/ai.ts": f"const c = new {sdk}({{\n  apiKey: key,\n  dangerouslyAllowBrowser: true,\n}});\n"})
    [f] = only(scan(root), "KLC003")
    assert f.severity == "high" and f.line == 3 and f.extra["provider"] == prov
    assert "dangerouslyAllowBrowser" in f.fix and "small backend" in f.fix


def test_dangerously_allow_browser_unknown_file_still_reported(make_repo):
    root = make_repo({"lib/ai.js": "export const c = new OpenAI({ dangerouslyAllowBrowser: true });\n"})
    assert len(only(scan(root), "KLC003")) == 1


def test_dangerously_allow_browser_in_server_file_ignored(make_repo):
    root = make_repo({**NEXT, "app/api/x/route.ts": "const c = new OpenAI({ dangerouslyAllowBrowser: true });\n",
                      "scripts/seed.ts": "const c = new OpenAI({ dangerouslyAllowBrowser: true });\n"})
    assert only(scan(root), "KLC003") == []


def test_google_genai_in_vite_client(make_repo):
    root = make_repo({**VITE, "services/gemini.ts": "const ai = new GoogleGenAI({ apiKey: process.env.API_KEY });\n"})
    [f] = only(scan(root), "KLC003")
    assert f.extra["provider"] == "gemini" and "x-goog-api-key" in f.fix


def test_google_genai_in_next_server_module_is_fine(make_repo):
    root = make_repo({**NEXT, "lib/gemini.ts": "const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });\n"})
    assert only(scan(root), "KLC003") == []                # app-router module: not known to be client


def test_ai_sdk_provider_factory_in_client(make_repo):
    root = make_repo({**NEXT, "components/Chat.tsx": '"use client";\nconst p = createOpenAI({ apiKey: k });\n'})
    [f] = only(scan(root), "KLC003")
    assert f.extra["provider"] == "openai"


@pytest.mark.parametrize("host", ["api.openai.com/v1/responses", "api.anthropic.com/v1/messages",
                                  "generativelanguage.googleapis.com/v1beta/models/x:generateContent",
                                  "api.groq.com/openai/v1/chat/completions", "api.mistral.ai/v1/chat/completions",
                                  "openrouter.ai/api/v1/chat/completions"])
def test_direct_fetch_with_auth_from_client(make_repo, host):
    root = make_repo({**NEXT, "components/X.tsx": f'"use client";\nfetch("https://{host}", {{ headers: '
                                                  f'{{ Authorization: "Bearer " + k }} }});\n'})
    [f] = only(scan(root), "KLC003")
    assert f.line == 2


def test_direct_fetch_without_auth_or_from_server_not_flagged(make_repo):
    root = make_repo({**NEXT,
                      "components/Docs.tsx": '"use client";\nconst link = "https://api.openai.com/docs";\n',
                      "app/api/ai/route.ts": 'fetch("https://api.openai.com/v1/responses", '
                                             '{ headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } });\n',
                      "lib/ai.ts": 'fetch("https://api.openai.com/v1/responses", { headers: { Authorization: k } });\n'})
    assert only(scan(root), "KLC003") == []


# ---------------------------------------------------------------- KLC004
@pytest.mark.parametrize("key,label", [
    ("openai", "OpenAI"), ("anthropic", "Anthropic"), ("groq", "Groq"), ("openrouter", "OpenRouter"),
    ("hf", "Hugging Face"), ("stripe_live", "Stripe live"), ("service_jwt", "service_role"), ("aws", "AWS"),
    ("github", "GitHub"), ("slack", "Slack"), ("sendgrid", "SendGrid"), ("resend", "Resend"),
])
def test_hard_coded_token_in_client_code_is_critical(make_repo, fake, key, label):
    root = make_repo({**VITE, "src/config.ts": f'export const KEY = "{fake[key]}";\n'})
    [f] = only(scan(root), "KLC004")
    assert f.severity == "critical" and label in f.message and f.line == 1
    assert fake[key] not in f.evidence and "****" in f.evidence


def test_hard_coded_token_in_server_code_is_high(make_repo, fake):
    root = make_repo({**NEXT, "app/api/x/route.ts": f'const k = "{fake["openai"]}";\n'})
    [f] = only(scan(root), "KLC004")
    assert f.severity == "high" and "server-side" in f.message


def test_stripe_test_key_is_medium(make_repo, fake):
    root = make_repo({**VITE, "src/pay.ts": f'const k = "{fake["stripe_test"]}";\n'})
    [f] = only(scan(root), "KLC004")
    assert f.severity == "medium"


def test_gemini_key_needs_gemini_context(make_repo, fake):
    root = make_repo({**VITE,
                      "src/firebase.ts": f'initializeApp({{ apiKey: "{fake["firebase"]}", authDomain: "x.firebaseapp.com" }});\n',
                      "src/gemini.ts": f'import {{ GoogleGenAI }} from "@google/genai";\nconst KEY = "{fake["gemini"]}";\n'})
    found = only(scan(root), "KLC004")
    assert [(f.file, f.line) for f in found] == [("src/gemini.ts", 2)]


@pytest.mark.parametrize("value", [
    "sk-" + "proj-" + "x" * 48,
    "sk-" + "proj-" + "your-api-key-goes-here-0000000000000000000000",
    "sk_" + "live_" + "0123456789abcdefghijABCDEFGHIJ",
    "AKIA" + "IOSFODNN7EXAMPLE",
    "gh" + "p_" + "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
    "sk-" + "ant-" + "api03-" + "REPLACE_ME_REPLACE_ME_REPLACE_ME_REPLACE",
])
def test_placeholders_not_flagged(make_repo, value):
    root = make_repo({**VITE, "src/config.ts": f'const KEY = "{value}";\n', "README.md": f"Set `{value}`\n"})
    assert only(scan(root), "KLC004") == []


def test_publishable_keys_in_code_not_flagged(make_repo, fake):
    root = make_repo({**NEXT, "app/pay.tsx": f'"use client";\nloadStripe("{fake["stripe_pk"]}");\n'
                                             f'createClient("https://x.supabase.co", "{fake["anon_jwt"]}");\n'
                                             f'new Razorpay({{ key: "{fake["razorpay_id"]}" }});\n'})
    assert scan(root) == []


def test_token_in_non_code_text_files(make_repo, fake):
    root = make_repo({"public/config.json": f'{{"openaiKey": "{fake["openai"]}"}}',
                      "docs/setup.md": f"Use this key: {fake['anthropic']}\n"})
    found = only(scan(root), "KLC004")
    assert sorted(f.file for f in found) == ["docs/setup.md", "public/config.json"]
    assert all(f.severity == "critical" for f in found)


def test_ignore_comment_and_lockfiles(make_repo, fake):
    root = make_repo({**VITE, "src/a.ts": f'const k = "{fake["openai"]}"; // key-leak-check: ignore\n',
                      "package-lock.json": f'{{"x": "{fake["openai"]}"}}'})
    assert scan(root) == []


def test_test_folders_skipped_unless_included(make_repo, fake):
    root = make_repo({**VITE, "tests/a.test.ts": f'const k = "{fake["openai"]}";\n',
                      "src/b.spec.ts": f'const k = "{fake["openai"]}";\n'})
    assert scan(root) == []
    assert len(only(scan(root, include_tests=True), "KLC004")) == 2


def test_exclude_glob(make_repo, fake):
    root = make_repo({**VITE, "src/a.ts": f'const k = "{fake["openai"]}";\n', "docs/x.md": f"{fake['groq']}\n"})
    assert [f.file for f in scan(root, excludes=["docs/*"])] == ["src/a.ts"]
    assert scan(root, excludes=["src", "docs"]) == []


def test_private_key_needs_body(make_repo):
    header = "-----BEGIN " + "PRIVATE KEY-----"
    root = make_repo({"docs/a.md": f"Paste your {header} here\n",
                      "src/k.ts": f'const k = "{header}\\n' + "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7" * 2 + '";\n'})
    found = only(scan(root), "KLC004")
    assert [f.file for f in found] == ["src/k.ts"]


def test_fullstack_vite_frameworks_are_not_treated_as_spa(make_repo):
    loader = ('export async function loader() {\n  return fetch("https://api.openai.com/v1/models", '
              '{ headers: { Authorization: `Bearer ${process.env.OPENAI_API_KEY}` } });\n}\n')
    root = make_repo({"package.json": {"devDependencies": {"@react-router/dev": "7.0.0", "vite": "7.0.0"}},
                      "app/routes/models.tsx": loader,
                      "app/lib/ai.client.ts": "const c = new GoogleGenAI({ apiKey: k });\n"})
    found = scan(root)
    assert [(f.rule_id, f.file) for f in found] == [("KLC003", "app/lib/ai.client.ts")]
