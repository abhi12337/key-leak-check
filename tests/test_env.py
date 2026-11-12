"""KLC001 (public env vars holding secrets), KLC007 (.env not ignored), KLC008 (templates)."""

import pytest

from key_leak_check.scanner import scan_path


def scan(root, **kw):
    return scan_path(str(root), **kw).findings


def only(findings, rule):
    return [f for f in findings if f.rule_id == rule]


IGNORE_ALL = ".env*\n!.env.example\n"


# ---------------------------------------------------------------- KLC001 true positives
@pytest.mark.parametrize("var,key", [
    ("NEXT_PUBLIC_OPENAI_API_KEY", "openai"),
    ("VITE_OPENAI_API_KEY", "openai"),
    ("REACT_APP_OPENAI_KEY", "openai"),
    ("EXPO_PUBLIC_ANTHROPIC_API_KEY", "anthropic"),
    ("PUBLIC_GROQ_API_KEY", "groq"),
    ("NUXT_PUBLIC_OPENROUTER_API_KEY", "openrouter"),
    ("VITE_GEMINI_API_KEY", "gemini"),
    ("NEXT_PUBLIC_GOOGLE_GENERATIVE_AI_API_KEY", "gemini"),
    ("NEXT_PUBLIC_STRIPE_SECRET_KEY", "stripe_live"),
    ("VITE_STRIPE_KEY", "stripe_live"),                  # generic name, secret value
    ("NEXT_PUBLIC_RAZORPAY_KEY_SECRET", "razorpay_secret"),
    ("NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY", "service_jwt"),
    ("VITE_SUPABASE_KEY", "service_jwt"),               # anon-looking name, service_role value
    ("NEXT_PUBLIC_AWS_SECRET_ACCESS_KEY", "aws_secret"),
    ("VITE_AWS_ACCESS_KEY", "aws"),
    ("NEXT_PUBLIC_SENDGRID_API_KEY", "sendgrid"),
    ("NEXT_PUBLIC_RESEND_API_KEY", "resend"),
    ("EXPO_PUBLIC_TWILIO_AUTH_TOKEN", "twilio_token"),
    ("NEXT_PUBLIC_GITHUB_TOKEN", "github"),
    ("VITE_HF_TOKEN", "hf"),
    ("NEXT_PUBLIC_DATABASE_URL", "db_url"),
])
def test_secret_in_public_env_var_is_critical(make_repo, fake, var, key):
    root = make_repo({".gitignore": IGNORE_ALL, ".env.local": f"# comment\n{var}={fake[key]}\n"})
    [f] = only(scan(root), "KLC001")
    assert f.severity == "critical"
    assert (f.file, f.line) == (".env.local", 2)
    assert fake[key] not in f.evidence and fake[key] not in f.message
    assert "****" in f.evidence
    assert f.extra["var"] == var


def test_quoted_and_exported_values(make_repo, fake):
    root = make_repo({".gitignore": IGNORE_ALL,
                      ".env": f'export NEXT_PUBLIC_OPENAI_API_KEY="{fake["openai"]}"\n'
                              f"VITE_ANTHROPIC_API_KEY='{fake['anthropic']}'  # oops\n"})
    assert [f.line for f in only(scan(root), "KLC001")] == [1, 2]


def test_fix_shows_rename_rotation_and_proxy(make_repo, fake):
    root = make_repo({"package.json": {"dependencies": {"next": "15.0.0"}}, ".gitignore": IGNORE_ALL,
                      ".env.local": f"NEXT_PUBLIC_OPENAI_API_KEY={fake['openai']}\n"})
    [f] = only(scan(root), "KLC001")
    assert "NEXT_PUBLIC_OPENAI_API_KEY  ->  OPENAI_API_KEY" in f.fix
    assert "platform.openai.com" in f.fix and "Rotate" in f.fix
    assert "app/api/ai/route.ts" in f.fix and "process.env.OPENAI_API_KEY" in f.fix
    assert "Vite" not in f.fix                        # only the detected framework's snippet


def test_fix_for_vite_shows_backend_proxy(make_repo, fake):
    root = make_repo({"package.json": {"devDependencies": {"vite": "7.0.0"}}, ".gitignore": IGNORE_ALL,
                      ".env": f"VITE_ANTHROPIC_API_KEY={fake['anthropic']}\n"})
    [f] = only(scan(root), "KLC001")
    assert "small backend" in f.fix and '"x-api-key": process.env.ANTHROPIC_API_KEY!' in f.fix
    assert "VITE_ANTHROPIC_API_KEY  ->  ANTHROPIC_API_KEY" in f.fix


def test_nuxt_and_sveltekit_names(make_repo, fake):
    root = make_repo({"package.json": {"dependencies": {"nuxt": "4.0.0"}}, ".gitignore": IGNORE_ALL,
                      ".env": f"NUXT_PUBLIC_OPENAI_API_KEY={fake['openai']}\n"})
    [f] = only(scan(root), "KLC001")
    assert "NUXT_OPENAI_API_KEY" in f.fix and "useRuntimeConfig(event).openaiApiKey" in f.fix


# ---------------------------------------------------------------- KLC001 clean
@pytest.mark.parametrize("line", [
    "NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY={stripe_pk}",
    "VITE_STRIPE_KEY={stripe_pk}",
    "NEXT_PUBLIC_SUPABASE_ANON_KEY={anon_jwt}",
    "VITE_SUPABASE_KEY={anon_jwt}",
    "NEXT_PUBLIC_FIREBASE_API_KEY={firebase}",
    "VITE_FIREBASE_API_KEY={firebase}",
    "NEXT_PUBLIC_GOOGLE_MAPS_API_KEY={firebase}",
    "NEXT_PUBLIC_RAZORPAY_KEY_ID={razorpay_id}",
    "NEXT_PUBLIC_RAZORPAY_KEY={razorpay_id}",
    "NEXT_PUBLIC_SUPABASE_URL=https://abcdefghijklmnop.supabase.co",
    "NEXT_PUBLIC_OPENAI_MODEL=gpt-4o-mini",
    "NEXT_PUBLIC_SHOW_PASSWORD_FIELD=true",
    "NEXT_PUBLIC_CLERK_PUBLISHABLE_KEY={stripe_pk}",
    "VITE_DATABASE_URL=postgresql://postgres:postgres@localhost:5432/postgres",
    "NEXT_PUBLIC_POSTHOG_KEY=phc_{generic}",
    "NEXT_PUBLIC_RECAPTCHA_SITE_KEY={generic}",
    "OPENAI_API_KEY={openai}",                                   # server-only name: fine
    "STRIPE_SECRET_KEY={stripe_live}",
    "SUPABASE_SERVICE_ROLE_KEY={service_jwt}",
    "NEXT_PUBLIC_API_KEY={generic}",                             # unknown format, generic name
])
def test_public_by_design_and_server_vars_not_flagged(make_repo, fake, line):
    root = make_repo({".gitignore": IGNORE_ALL, ".env": line.format(**fake) + "\n"})
    assert only(scan(root), "KLC001") == []


def test_supabase_local_demo_service_key_not_flagged(make_repo):
    from conftest import fake_jwt
    root = make_repo({".gitignore": IGNORE_ALL,
                      ".env": f"VITE_SUPABASE_KEY={fake_jwt('service' + '_role', iss='supabase-demo')}\n"})
    assert only(scan(root), "KLC001") == []


@pytest.mark.parametrize("value", ["", "your-openai-key", "sk-proj-...", "<your key>", "sk-proj-xxxxxxxxxxxxxxxxxxxx",
                                   "${OPENAI_API_KEY}"])
def test_public_secret_name_without_value_is_high(make_repo, value):
    root = make_repo({".gitignore": IGNORE_ALL, ".env.local": f"NEXT_PUBLIC_OPENAI_API_KEY={value}\n"})
    [f] = only(scan(root), "KLC001")
    assert f.severity == "high" and "public prefix" in f.message


def test_public_password_flag_without_value_not_flagged(make_repo):
    root = make_repo({".gitignore": IGNORE_ALL, ".env": "NEXT_PUBLIC_RESET_PASSWORD=\nVITE_STRIPE_KEY=\n"})
    assert only(scan(root), "KLC001") == []


def test_ignore_comment_in_env(make_repo, fake):
    root = make_repo({".gitignore": IGNORE_ALL,
                      ".env": f"VITE_OPENAI_API_KEY={fake['openai']} # key-leak-check: ignore\n"})
    assert only(scan(root), "KLC001") == []


# ---------------------------------------------------------------- KLC001 in config files
@pytest.mark.parametrize("rel,content", [
    ("Dockerfile", "FROM node:22\nENV NEXT_PUBLIC_OPENAI_API_KEY={openai}\nRUN npm run build\n"),
    ("Dockerfile", "FROM node:22\nARG VITE_GROQ_API_KEY={groq}\n"),
    ("vercel.json", '{{"build": {{"env": {{"NEXT_PUBLIC_ANTHROPIC_API_KEY": "{anthropic}"}}}}}}'),
    (".github/workflows/deploy.yml", "jobs:\n  b:\n    env:\n      VITE_OPENAI_API_KEY: {openai}\n"),
    ("netlify.toml", '[build.environment]\n  VITE_STRIPE_SECRET_KEY = "{stripe_live}"\n'),
    ("next.config.mjs", 'export default {{ env: {{ NEXT_PUBLIC_OPENAI_API_KEY: "{openai}" }} }};\n'),
])
def test_secret_in_public_var_in_config_files(make_repo, fake, rel, content):
    root = make_repo({rel: content.format(**fake)})
    found = scan(root)
    k1 = only(found, "KLC001")
    assert len(k1) == 1 and k1[0].severity == "critical" and k1[0].file == rel
    assert only(found, "KLC004") == []                     # same line is not reported twice


def test_config_references_are_not_flagged(make_repo):
    root = make_repo({
        ".github/workflows/deploy.yml": "env:\n  VITE_OPENAI_API_KEY: ${{ secrets.OPENAI_KEY }}\n"
                                        "  NEXT_PUBLIC_SUPABASE_URL: https://x.supabase.co\n",
        "Dockerfile": "ARG NEXT_PUBLIC_OPENAI_API_KEY\nENV NEXT_PUBLIC_OPENAI_API_KEY=$NEXT_PUBLIC_OPENAI_API_KEY\n",
    })
    assert only(scan(root), "KLC001") == []


# ---------------------------------------------------------------- KLC007
def test_env_tracked_by_git_is_high(make_repo, fake):
    root = make_repo({".env": f"OPENAI_API_KEY={fake['openai']}\n", ".gitignore": ".env\n"}, git=True, add=[".env"])
    [f] = only(scan(root), "KLC007")
    assert f.severity == "high" and "tracked by git" in f.message and "OPENAI_API_KEY" in f.message


def test_env_not_ignored_in_git_repo_is_high(make_repo, fake):
    root = make_repo({".env.local": f"STRIPE_SECRET_KEY={fake['stripe_live']}\n"}, git=True)
    [f] = only(scan(root), "KLC007")
    assert f.severity == "high" and "not git-ignored" in f.message


def test_env_ignored_in_git_repo_is_fine(make_repo, fake):
    root = make_repo({".env.local": f"STRIPE_SECRET_KEY={fake['stripe_live']}\n", ".gitignore": ".env*.local\n"},
                     git=True)
    assert only(scan(root), "KLC007") == []


def test_env_without_gitignore_outside_git(make_repo, fake):
    root = make_repo({"apps/web/.env": f"DATABASE_URL={fake['db_url']}\n"})
    [f] = only(scan(root), "KLC007")
    assert f.file == "apps/web/.env"


@pytest.mark.parametrize("gitignore_rel,pattern", [
    (".gitignore", ".env"), (".gitignore", ".env*"), (".gitignore", "*.env"),
    ("apps/web/.gitignore", ".env"), (".gitignore", "apps/web/.env"), (".gitignore", "/apps/**/.env"),
])
def test_gitignore_patterns_outside_git(make_repo, fake, gitignore_rel, pattern):
    root = make_repo({"apps/web/.env": f"OPENAI_API_KEY={fake['openai']}\n", gitignore_rel: pattern + "\n"})
    assert only(scan(root), "KLC007") == []


def test_gitignore_negation(make_repo, fake):
    root = make_repo({".env.production": f"OPENAI_API_KEY={fake['openai']}\n",
                      ".gitignore": ".env*\n!.env.production\n"})
    assert len(only(scan(root), "KLC007")) == 1


def test_env_with_only_public_config_is_not_klc007(make_repo, fake):
    root = make_repo({".env": f"VITE_SUPABASE_URL=https://abc.supabase.co\nVITE_SUPABASE_ANON_KEY={fake['anon_jwt']}\n"
                              f"VITE_STRIPE_PUBLISHABLE_KEY={fake['stripe_pk']}\n"})
    assert scan(root) == []


# ---------------------------------------------------------------- KLC008
def test_template_with_real_looking_key_is_medium(make_repo, fake):
    root = make_repo({".env.example": f"OPENAI_API_KEY={fake['openai']}\nRAZORPAY_KEY_SECRET={fake['razorpay_secret']}\n"
                                      "RESEND_API_KEY=re_your_key\n"})
    found = only(scan(root), "KLC008")
    assert [(f.severity, f.line) for f in found] == [("medium", 1), ("medium", 2)]
    assert only(scan(root), "KLC007") == []                # templates are meant to be committed


def test_template_public_secret_name_is_high_and_value_also_klc008(make_repo, fake):
    root = make_repo({".env.sample": f"VITE_OPENAI_API_KEY={fake['openai']}\n"})
    found = scan(root)
    assert [(f.rule_id, f.severity) for f in found] == [("KLC001", "high"), ("KLC008", "medium")]


def test_clean_template_fixture(copy_fixture):
    root = copy_fixture("next_clean")
    assert scan(root) == []
