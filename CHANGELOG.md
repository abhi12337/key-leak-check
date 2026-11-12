# Changelog

All notable changes to this project are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/) and the project uses
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-11

First release.

### Added

- `key-leak-check scan [PATH ...]`: static scan of project folders or single files for
  secret API keys that end up in the browser. Never builds, runs or connects to anything;
  no network access. Secrets are never printed: at most the first 4 characters plus the
  length, in text and JSON output.
- `key-leak-check rules`: every rule with why it matters and how to fix it.
- Framework detection per package (Next.js, Vite, Create React App, Expo, SvelteKit, Nuxt,
  Astro; Remix / React Router / TanStack Start and similar treated as mixed server/client)
  and a client / server classification of each file.
- Rules:
  - KLC001 secrets in browser-exposed env vars (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`,
    `EXPO_PUBLIC_`, `PUBLIC_`, `NUXT_PUBLIC_`) in `.env*` files, Dockerfiles, CI workflows and
    deploy / framework configs
  - KLC002 client code reading a secret through a public env var, and secrets inlined by
    vite.config `define`, next.config `env`, Expo `extra` and Nuxt `runtimeConfig.public`
  - KLC003 AI APIs called directly from the browser (`dangerouslyAllowBrowser`, Google GenAI
    SDK in client code, AI SDK provider factories with `apiKey`, `fetch` to AI APIs with an
    auth header)
  - KLC004 hard-coded keys in known formats, with a placeholder / entropy filter
  - KLC005 keys inside built bundles (`dist/`, `build/`, `out/`, `.next/static`, ...)
  - KLC006 source maps shipped with the build
  - KLC007 `.env` files with secrets that are tracked by git or not git-ignored
  - KLC008 real-looking keys in `.env.example` / templates
- Publishable keys (Stripe `pk_`, Supabase anon, Firebase web `apiKey`, Razorpay key id, ...)
  are recognised and never reported.
- Fixes written for each finding's provider and framework: rotation (where to do it),
  the correct server-side env var name, and a server-side proxy snippet.
- Text and JSON reports, `--fail-on`, `--min-severity`, `--disable`, `--exclude`,
  `--include-tests`, `--[no-]include-build`, `--brief`, `--no-color`,
  `key-leak-check: ignore` comments, exit codes `0` / `1` / `2`.
- Demo project generator (`examples/make_demo.py`) and a GitHub Actions example.
