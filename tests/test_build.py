"""KLC005 (keys inside built bundles) and KLC006 (shipped source maps)."""

import pytest

from key_leak_check.scanner import scan_path


def scan(root, **kw):
    return scan_path(str(root), **kw)


def only(findings, rule):
    return [f for f in findings if f.rule_id == rule]


def bundle(secret: str) -> str:
    return "!function(){var a=1;" * 300 + f'fetch(u,{{headers:{{Authorization:"Bearer {secret}"}}}})' + "}();"


@pytest.mark.parametrize("rel", [
    "dist/assets/index-abc123.js",
    "build/static/js/main.4f2a.js",
    "out/_next/static/chunks/app.js",
    "web-build/static/js/app.js",
    ".next/static/chunks/pages/index-9f8e.js",
    ".output/public/_nuxt/entry.js",
    ".svelte-kit/output/client/_app/immutable/entry/app.js",
    "apps/web/dist/assets/index.js",
    "dist/index.html",
])
def test_key_in_bundle_is_critical(make_repo, fake, rel):
    root = make_repo({rel: bundle(fake["openai"])})
    res = scan(root)
    [f] = only(res.findings, "KLC005")
    assert f.severity == "critical" and f.file == rel and f.line == 1
    assert f.evidence == "sk-p**** (128 chars)"
    assert res.build_files == 1 and res.build_dirs


@pytest.mark.parametrize("rel", [".next/server/app/page.js", "dist/server/entry.mjs", "build/server/index.js",
                                 ".next/cache/x.js", ".output/server/index.mjs", ".vercel/output/functions/a.js"])
def test_server_bundles_not_scanned(make_repo, fake, rel):
    root = make_repo({rel: bundle(fake["openai"])})
    assert scan(root).findings == []


def test_service_role_and_gemini_in_bundle(make_repo, fake):
    js = (f'const s=createClient("https://x.supabase.co","{fake["service_jwt"]}");'
          f'const g="https://generativelanguage.googleapis.com";const k="{fake["gemini"]}";')
    root = make_repo({"dist/assets/a.js": js})
    labels = sorted(f.message.split(" found")[0] for f in only(scan(root).findings, "KLC005"))
    assert labels == ["Google Gemini API key", "Supabase service_role JWT"]


def test_publishable_keys_in_bundle_not_flagged(make_repo, fake):
    js = (f'loadStripe("{fake["stripe_pk"]}");createClient("https://x.supabase.co","{fake["anon_jwt"]}");'
          f'initializeApp({{apiKey:"{fake["firebase"]}",authDomain:"x.firebaseapp.com"}});')
    root = make_repo({"dist/assets/a.js": js, "dist/assets/a.css": "body{color:red}"})
    assert scan(root).findings == []


def test_no_include_build(make_repo, fake):
    root = make_repo({"dist/assets/a.js": bundle(fake["openai"]), "dist/assets/a.js.map": "{}"})
    res = scan(root, include_build=False)
    assert res.findings == [] and res.build_files == 0


def test_source_maps_one_finding_per_build_dir(make_repo):
    root = make_repo({"dist/assets/a.js": "x", "dist/assets/a.js.map": "{}", "dist/assets/b.js.map": "{}",
                      ".next/static/chunks/c.js.map": "{}"})
    found = only(scan(root).findings, "KLC006")
    assert sorted((f.severity, f.file) for f in found) == [("medium", ".next/static/chunks/c.js.map"),
                                                           ("medium", "dist/assets/a.js.map")]
    assert "2 source map file(s) in dist/" in [f.message for f in found if f.file.startswith("dist")][0]
    assert "sourcemap: false" in found[0].fix


def test_maps_outside_build_dirs_ignored(make_repo):
    root = make_repo({"src/vendor/lib.js.map": "{}", "public/lib.min.js.map": "{}"})
    assert scan(root).findings == []


def test_bundle_secret_not_double_reported_as_klc004(make_repo, fake):
    root = make_repo({"dist/a.js": bundle(fake["anthropic"])})
    assert [f.rule_id for f in scan(root).findings] == ["KLC005"]
