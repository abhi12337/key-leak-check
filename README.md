# key-leak-check

Find secret API keys that end up in the **browser**. Built for people shipping AI apps on
Next.js, Vite / React, Create React App, Expo, SvelteKit, Nuxt and Astro, where the most
common leak is not a committed `.env` file but an OpenAI / Anthropic / Gemini / Stripe key
that the bundler quietly copies into the JavaScript every visitor downloads.

It finds:

1. **Secrets in browser-exposed env vars**: `NEXT_PUBLIC_*`, `VITE_*`, `REACT_APP_*`,
   `EXPO_PUBLIC_*`, `PUBLIC_*`, `NUXT_PUBLIC_*` holding an AI key, a Stripe / Razorpay secret,
   a Supabase `service_role` key, an AWS secret, a database URL with a password, ...
   in `.env*` files, Dockerfiles, CI workflows, `vercel.json`, `netlify.toml` and framework configs.
2. **Client code that reads a secret through a public env var** (`process.env.NEXT_PUBLIC_OPENAI_API_KEY`,
   `import.meta.env.VITE_ANTHROPIC_API_KEY`, `$env/static/public`, Nuxt `runtimeConfig.public`),
   and build configs that inline secrets anyway (vite.config `define`, next.config `env`, Expo `extra`).
3. **AI APIs called straight from the browser**: `new OpenAI({ dangerouslyAllowBrowser: true })`,
   the Anthropic / Groq SDKs with the same flag, `new GoogleGenAI(...)` in client code, and
   `fetch("https://api.openai.com/...")` with an `Authorization` header from client components.
4. **Hard-coded keys** in known formats (`sk-proj-`, `sk-ant-`, `gsk_`, `AKIA`, `ghp_`, `sk_live_`,
   `xoxb-`, `SG.`, `re_`, service_role JWTs, ...), with a placeholder / entropy filter.
5. **Keys inside built bundles** (`dist/`, `build/`, `out/`, `.next/static`, ...) and **shipped
   source maps**.
6. **`.env` files with secrets that are committed or not git-ignored**, and `.env.example`
   files holding real-looking keys.

Every finding has a rule id, a severity, `file:line`, the offending line with the secret
redacted, why it matters, and an exact fix: key rotation (with where to do it for that
provider), the correct server-side env var name, and a server-side proxy for the framework
the file belongs to (Next.js route handler, a small backend for Vite / CRA, SvelteKit
`+server.ts`, Nuxt `server/api`, Astro endpoint, Expo API route).

Zero dependencies (Python 3.10+ standard library only). **Static only:** it never builds,
runs or connects to anything and makes no network requests. **It never prints a secret:**
values are shown as at most the first 4 characters plus the length (`sk-p**** (128 chars)`),
in text and JSON output alike. CI-friendly exit codes.

---

## Quick start

```bash
pipx install .                          # from a clone of this repo (or: pip install .)

key-leak-check scan                     # current folder (source, env files, build output)
key-leak-check scan path/to/app path/to/other-app
key-leak-check scan apps/web/.env.local # a single file
key-leak-check scan . --json > report.json
key-leak-check rules                    # every rule, why it matters, how to fix it
```

Build your app first (`npm run build`) and scan again: the build output is where a leaked
key really ends up, and it is scanned automatically when `dist/`, `build/`, `out/`,
`.next/static`, `.output/public`, `.svelte-kit/output/client` or `web-build/` exist
(`--no-include-build` to skip it).

Try it on the deliberately leaky demo project (a Next.js app and a Vite + Gemini app):

```bash
python examples/make_demo.py demo-ai-app
key-leak-check scan demo-ai-app
```

Exit codes: `0` = nothing at or above `--fail-on` (default `high`), `1` = findings at or above
it, `2` = usage error. Use `--fail-on critical|high|medium|low|info|never` to tune CI.

## Example output

All output below was produced by running this version of the tool on the demo project and
the test fixtures in this repository (nothing is hand-edited). The keys in the demo are
random text generated at run time; they are redacted in the output like real ones.

`key-leak-check scan demo-ai-app --brief`:

```text
key-leak-check 0.1.0
Scanned demo-ai-app
14 file(s): 3 env file(s), 8 source file(s), 3 built file(s) in studio/dist/, web/.next/static/
Frameworks: next, vite

CRITICAL KLC001  Secret in a browser-exposed env var
      at: web/.env.local:3
      Supabase service_role JWT in NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY: the public prefix makes
      the bundler inline it into the JavaScript every visitor downloads.
      code: NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY=eyJh**** (219 chars)

CRITICAL KLC001  Secret in a browser-exposed env var
      at: web/.env.local:6
      OpenAI API key in NEXT_PUBLIC_OPENAI_API_KEY: the public prefix makes the bundler inline it
      into the JavaScript every visitor downloads.
      code: NEXT_PUBLIC_OPENAI_API_KEY=sk-p**** (128 chars)

CRITICAL KLC002  Client code reads a secret through a public env var
      at: studio/src/lib/groq.ts:6
      import.meta.env reads VITE_GROQ_API_KEY in browser code: the bundler replaces it with the
      secret value in the JavaScript every visitor downloads.
      code: Authorization: `Bearer ${import.meta.env.VITE_GROQ_API_KEY}`,

CRITICAL KLC002  Client code reads a secret through a public env var
      at: studio/vite.config.ts:9
      process.env.GEMINI_API_KEY is inlined into the client bundle by vite.config `define`: the
      secret value ships to every visitor even though it has no public prefix.
      code: "process.env.GEMINI_API_KEY": JSON.stringify(env.GEMINI_API_KEY),

CRITICAL KLC002  Client code reads a secret through a public env var
      at: web/app/chat/page.tsx:6
      process.env reads NEXT_PUBLIC_OPENAI_API_KEY in browser code: the bundler replaces it with
      the secret value in the JavaScript every visitor downloads.
      code: apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,

CRITICAL KLC004  API key hard-coded in source
      at: web/lib/summarise.ts:3
      Anthropic API key hard-coded in source code.
      code: const ANTHROPIC_KEY = "sk-a**** (106 chars)";

CRITICAL KLC005  API key inside built JavaScript bundle
      at: studio/dist/assets/index-4f9a1c.js:1
      Google Gemini API key found in built file served to browsers (studio/dist/).
      code: AIza**** (39 chars)

CRITICAL KLC005  API key inside built JavaScript bundle
      at: web/.next/static/chunks/app/chat/page-8f3a21c9.js:1
      OpenAI API key found in built file served to browsers (web/.next/static/).
      code: sk-p**** (128 chars)

HIGH     KLC001  Secret in a browser-exposed env var
      at: studio/.env.example:2
      VITE_GROQ_API_KEY names a secret (Groq) but has a public prefix: this template tells
      everyone to put the key in a variable the bundler ships to the browser.
      code: VITE_GROQ_API_KEY=

HIGH     KLC003  AI API called directly from the browser
      at: studio/services/geminiService.ts:3
      new GoogleGenAI(...) in browser code: the Gemini API key it is given is readable by every
      visitor.
      code: const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

HIGH     KLC003  AI API called directly from the browser
      at: studio/src/lib/groq.ts:2
      Browser code calls api.groq.com directly with an API key header: the key is visible in every
      visitor's network tab.
      code: const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {

HIGH     KLC003  AI API called directly from the browser
      at: web/app/chat/page.tsx:7
      new OpenAI(...) is created with dangerouslyAllowBrowser: true, so it runs in the browser
      with your API key.
      code: dangerouslyAllowBrowser: true,

HIGH     KLC007  .env file with secrets committed or not git-ignored
      at: web/.env.local
      web/.env.local holds secrets (NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY, STRIPE_SECRET_KEY,
      NEXT_PUBLIC_OPENAI_API_KEY) and no .gitignore covers it.

MEDIUM   KLC006  Source maps shipped with the build
      at: studio/dist/assets/index-4f9a1c.js.map
      1 source map file(s) in studio/dist/ (e.g. studio/dist/assets/index-4f9a1c.js.map): anyone
      can rebuild your original source from the deployed site.

MEDIUM   KLC008  Real-looking key in an env example/template
      at: studio/.env.example:3
      RESEND_API_KEY in studio/.env.example holds a value that looks like a real Resend API key.
      Example files are committed and copied by everyone who clones the repo.
      code: RESEND_API_KEY=re_u**** (36 chars)

Summary: 8 critical, 5 high, 2 medium, 0 low, 0 info
Exit code: 1
```

Note what is **not** reported: the Supabase anon key, the Stripe publishable key, and
`STRIPE_SECRET_KEY` used from the server route handler `web/app/api/checkout/route.ts`.

A full finding (without `--brief`). The fix is written for the framework of the file
(here a Vite app) and the provider of the key:

```text
HIGH     KLC003  AI API called directly from the browser
      at: studio/services/geminiService.ts:3
      new GoogleGenAI(...) in browser code: the Gemini API key it is given is readable by every
      visitor.
      code: const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });
      why: An AI SDK created in browser code (`dangerouslyAllowBrowser: true`, `new
           GoogleGenAI(...)` in a client component) or a fetch to api.openai.com /
           api.anthropic.com with an Authorization header from client code needs the API key
           in the browser. Anyone can read it from the network tab and use your account; you
           also cannot rate-limit or authenticate who spends your tokens.
      fix:
        1. Remove the API key and the SDK client from browser code (drop
           `dangerouslyAllowBrowser`). If the key was ever deployed, rotate it.
           Where: aistudio.google.com/apikey or Google Cloud console -> Credentials -> delete the key.
        2. Keep the key in a server-only variable (GEMINI_API_KEY, no public prefix) and proxy the
           request through your own endpoint that checks the user and rate-limits:
           Vite / React (no server of its own): add a small backend, e.g. a Vercel/Netlify function
           api/ai.ts or an Express server, and proxy /api to it in dev (vite.config server.proxy):
             app.post("/api/ai", async (req, res) => {
               // check the user and rate-limit here: this endpoint spends your money
               const r = await fetch("https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent", { method: "POST",
                 headers: { "Content-Type": "application/json", "x-goog-api-key": process.env.GEMINI_API_KEY! },
                 body: JSON.stringify({ /* model + validated prompt; never forward the raw body */ }) });
               res.status(r.status).json(await r.json());
             });
             browser:  await fetch("/api/ai", { method: "POST", body: JSON.stringify({ prompt }) })
```

A finding in the Next.js app gets a route handler instead:

```text
CRITICAL KLC001  Secret in a browser-exposed env var
      at: web/.env.local:6
      OpenAI API key in NEXT_PUBLIC_OPENAI_API_KEY: the public prefix makes the bundler inline it
      into the JavaScript every visitor downloads.
      code: NEXT_PUBLIC_OPENAI_API_KEY=sk-p**** (128 chars)
      fix:
        1. Rotate the key now. Every build made with the old value contains it, and old
           deploys and CDN caches keep serving it.
           Where: platform.openai.com -> API keys -> revoke.
        2. Rename it without the public prefix so the bundler never inlines it:
             NEXT_PUBLIC_OPENAI_API_KEY  ->  OPENAI_API_KEY
           Set OPENAI_API_KEY in .env.local (git-ignored) and in your host's environment settings.
        3. Use it only in server code, and let the browser call your endpoint instead:
           Next.js, app/api/ai/route.ts (runs only on the server; a "use server" action also works):
             export async function POST(req: Request) {
               // check the user's session and rate-limit here: this endpoint spends your money
               const { prompt } = await req.json();
               const r = await fetch("https://api.openai.com/v1/chat/completions", {
                 method: "POST",
                 headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
                 body: JSON.stringify({ /* model + validated prompt; never forward the raw body */ }),
               });
               return Response.json(await r.json(), { status: r.status });
             }
             browser:  await fetch("/api/ai", { method: "POST", body: JSON.stringify({ prompt }) })
```

Correct apps (`tests/fixtures/next_clean`, `tests/fixtures/vite_clean`: server route
handlers, a `"use server"` action, an `import "server-only"` module, publishable keys in
the browser, placeholder `.env.example`) produce no findings:

```text
key-leak-check 0.1.0
Scanned tests/fixtures/next_clean, tests/fixtures/vite_clean
11 file(s): 1 env file(s), 10 source file(s), 0 built file(s)
Frameworks: next, vite

No findings. (This is not a guarantee: see 'What it does not check' in the README.)
Summary: 0 critical, 0 high, 0 medium, 0 low, 0 info
Exit code: 0
```

## What it checks

| Rule | Severity | What it finds |
|---|---|---|
| KLC001 | Critical / High | A public-prefixed variable (`NEXT_PUBLIC_`, `VITE_`, `REACT_APP_`, `EXPO_PUBLIC_`, `PUBLIC_`, `NUXT_PUBLIC_`) that holds a secret, in `.env*` files, Dockerfiles (`ENV` / `ARG`), GitHub workflows, `vercel.json`, `netlify.toml`, compose files and framework configs. A secret is a known token format, a Supabase `service_role` JWT, a database URL with a non-default password on a non-local host, or a real-looking value in a variable whose name says it is secret (`OPENAI`, `ANTHROPIC`, `GEMINI`, `GROQ`, `MISTRAL`, `OPENROUTER`, ... `_API_KEY`; `*_SECRET*`, `SERVICE_ROLE`, `PRIVATE_KEY`, `AUTH_TOKEN`, `PASSWORD`). Critical with a value; High when the name is public and secret but the value is empty or a placeholder (the template tells people where to put the key). |
| KLC002 | Critical / Medium | Code that reads a secret-named public variable: `process.env.NEXT_PUBLIC_*` / `EXPO_PUBLIC_*` / `REACT_APP_*`, `import.meta.env.VITE_*` / `PUBLIC_*`, SvelteKit `$env/static/public` and `$env/dynamic/public`, Nuxt `useRuntimeConfig().public.*`. Also secrets inlined by vite.config `define` (including `"process.env.API_KEY": JSON.stringify(env.GEMINI_API_KEY)`), next.config `env`, Expo `extra` and Nuxt `runtimeConfig.public`. Medium when the file is server-only (still misnamed). |
| KLC003 | High | `dangerouslyAllowBrowser: true` (OpenAI, Anthropic, Groq, ... SDKs) outside server code; `new GoogleGenAI(...)` / `new GoogleGenerativeAI(...)` and Vercel AI SDK `createOpenAI({ apiKey })` etc. in browser code; `fetch` to `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com`, `api.groq.com`, `api.mistral.ai`, `openrouter.ai`, `api.perplexity.ai`, `api.x.ai`, ... from browser code that also sets an `Authorization` / `x-api-key` / `x-goog-api-key` header. |
| KLC004 | Critical / High / Medium | Known token formats hard-coded in any source or text file: OpenAI (`sk-proj-`, `sk-svcacct-`, `sk-admin-`, legacy), Anthropic (`sk-ant-`), OpenRouter, Groq (`gsk_`), xAI, Perplexity, Replicate, Hugging Face, ElevenLabs, Stripe (`sk_live_`, `rk_live_`, `whsec_`; `sk_test_` is Medium), Supabase `sb_secret_` and `service_role` JWTs, AWS (`AKIA`/`ASIA`), GitHub (`ghp_`, `github_pat_`, ...), Slack (`xoxb-`, ...), SendGrid, Resend, Twilio API keys, npm tokens, PEM private keys, and Google `AIza` keys only next to Gemini code. Critical in browser / unknown code, High in server-only code. Placeholders (`your-key`, `xxxx`, `...`, `EXAMPLE`, repeated or sequential characters, low entropy) are ignored. |
| KLC005 | Critical | The same token formats inside built files served to browsers: `.js`, `.mjs`, `.html` in `dist/`, `build/`, `out/`, `web-build/`, `.next/static/`, `.output/public/`, `.svelte-kit/output/client/`, `.vercel/output/static/`. Server bundles (`.next/server`, `dist/server`, `build/server`) are skipped. |
| KLC006 | Medium | `.map` source maps in those build folders (one finding per folder, with the count). |
| KLC007 | High | A real `.env*` file that holds secrets and is tracked by git, or is not git-ignored (checked with `git ls-files` / `git check-ignore`; outside a git repo, by reading the `.gitignore` files). Env files with only public config are not reported. |
| KLC008 | Medium | `.env.example` / `.sample` / `.template` / `.dist` / `.defaults` files with a value that looks like a real key. |

### Public by design: never reported

These keys are meant to be in the browser, so they are not findings (as long as the value
really is the public kind):

- Stripe **publishable** keys (`pk_live_...`, `pk_test_...`)
- Supabase **anon** keys (JWT with `role: anon`) and `sb_publishable_...` keys
- Firebase web config `apiKey` (`AIza...`) and Google Maps browser keys: restrict them by
  HTTP referrer and API in the Google Cloud console instead
- Razorpay **key id** (`rzp_live_...`, `rzp_test_...`); the key **secret** is reported
- Clerk publishable keys, PostHog project keys, reCAPTCHA / Turnstile site keys, Mapbox
  public tokens, Sentry DSNs, analytics ids

A Google `AIza...` key is reported only when it sits next to Gemini code
(`generativelanguage.googleapis.com`, `GoogleGenAI`, a `GEMINI_` name), and a Supabase key
only when its JWT role is `service_role`.

### How client and server code are told apart

The severity of KLC002 / KLC004 and whether KLC003 applies depend on whether a file runs in
the browser. Per package (nearest `package.json`), the framework is detected from its
dependencies, then:

- **Server**: `"use server"` / `import "server-only"`, Next.js `route.ts` and `middleware.ts`,
  `pages/api/`, `app/api/`, `*.server.*`, SvelteKit `+server.ts` / `+page.server.ts` /
  `$lib/server`, Nuxt `server/`, Expo `+api.ts`, and folders such as `api/`, `server/`,
  `functions/`, `netlify/`, `supabase/`, `scripts/`, plus `*.config.*` files.
- **Browser**: `"use client"`, `*.client.*`, `.svelte` / `.vue` components, files in `public/`,
  everything else in a Vite SPA, Create React App or Expo app, Next.js `pages/` and `hooks/`,
  SvelteKit universal `+page.ts`, Nuxt `components/`, `pages/`, `composables/`, `plugins/`.
- **Unknown**: everything else (for example Next.js app-router modules without a directive,
  Astro files, and route files in Remix / React Router / TanStack Start, which mix loaders
  and components). KLC003 does not fire on unknown files except for `dangerouslyAllowBrowser`;
  KLC002 / KLC004 treat them like browser code.

## What it does not check

Be clear about the limits before relying on it:

- **No guarantee.** A clean report means "none of these known patterns were found", nothing
  more. It is not a penetration test and it does not check your deployed site.
- **Static and pattern-based.** No JavaScript parser and no data flow: a key passed through
  a variable into another module, built from string pieces, base64-encoded, or fetched at
  run time from your own API is not followed. Comments are only skipped when the whole line
  is a comment.
- **Secrets without a recognisable format** (Razorpay key secret, Twilio auth token, AWS
  secret access key, Mistral and DeepSeek keys, ...) are only found when the variable name
  says what they are. A random value in `VITE_API_KEY` is not reported, because many
  public keys look the same.
- **Client / server detection is a heuristic** based on directives, file names, folders and
  the detected framework (see above). Unusual layouts can be misclassified; use
  `--exclude` or an ignore comment for false positives and tell us about them.
- **Only the build output that exists on disk is checked.** If you deploy from CI, run the
  build there before scanning. It does not download your deployed bundle.
- **Git history is not scanned.** A key that was committed and later deleted is still
  leaked. Use a history scanner (for example gitleaks or trufflehog) for that, and rotate.
- Source map contents are not searched; the maps are reported as a finding on their own.
- Test folders and `*.test.*` / `*.spec.*` files are skipped by default (`--include-tests`).

## How to fix the findings

`key-leak-check rules` prints all of this. Every finding in a report carries its own fix,
with the real variable name, provider and framework filled in. The pattern is always the same:

1. **Rotate the key** in the provider's dashboard. Once a key has been in a deployed bundle
   or a commit, assume it is public: removing it from the code does not un-leak it.
2. **Rename the variable without the public prefix** so the bundler cannot inline it:
   `NEXT_PUBLIC_OPENAI_API_KEY` -> `OPENAI_API_KEY`, `VITE_ANTHROPIC_API_KEY` -> `ANTHROPIC_API_KEY`,
   `PUBLIC_GEMINI_API_KEY` -> `GEMINI_API_KEY` (SvelteKit: `$env/static/private`), Nuxt:
   private `runtimeConfig` (`NUXT_OPENAI_API_KEY`). Remove it from vite.config `define`,
   next.config `env` and Expo `extra`.
3. **Call the provider from server code** and have the browser call your endpoint. Check
   the user's session and rate-limit there, and build the upstream request from validated
   input instead of forwarding the raw body (otherwise you have built a free proxy for
   your key).

Next.js (`app/api/ai/route.ts`, or a `"use server"` action):

```ts
export async function POST(req: Request) {
  // check the user's session and rate-limit here: this endpoint spends your money
  const { prompt } = await req.json();
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: String(prompt).slice(0, 4000) }] }),
  });
  return Response.json(await r.json(), { status: r.status });
}
// browser: await fetch("/api/ai", { method: "POST", body: JSON.stringify({ prompt }) })
```

Vite / React / CRA (no server of its own): add a small backend, such as a Vercel or Netlify
function (`api/ai.ts`) or an Express / Hono server, and proxy `/api` to it in development
with `server.proxy` in vite.config. Expo: an Expo Router API route (`app/api/ai+api.ts`) or
any backend; nothing inside the app bundle is secret.

Source maps (KLC006): `build.sourcemap: false` (Vite, SvelteKit, Astro, Nuxt),
`productionBrowserSourceMaps: false` (Next.js, the default), `GENERATE_SOURCEMAP=false` (CRA).

`.env` files (KLC007): ignore `.env`, `.env*.local` and `.env.*` (with `!.env.example`); if a
file was committed, `git rm --cached` it and rotate every key in it.

## Suppressing a finding

Add `key-leak-check: ignore` as a comment on the reported line (works in code, `.env` files,
YAML, TOML and Dockerfiles):

```ts
const demoKey = "..."; // key-leak-check: ignore  (revoked key used in a tutorial)
```

To turn a rule off for a whole run: `--disable KLC006` (repeatable). To skip paths:
`--exclude 'docs/*'` (repeatable).

## Use in CI

See [`examples/github-actions/key-leak-check.yml`](examples/github-actions/key-leak-check.yml).
It builds the app, scans source and build output on every pull request, fails on
Critical/High findings, and uploads the JSON report as an artifact.

## JSON output

`--json` prints (one finding shown, from the demo project):

```json
{
  "tool": "key-leak-check",
  "version": "0.1.0",
  "targets": [
    "/abs/path/demo-ai-app"
  ],
  "files_scanned": 14,
  "frameworks": [
    "next",
    "vite"
  ],
  "env_files": [
    "studio/.env",
    "studio/.env.example",
    "web/.env.local"
  ],
  "source_files": 8,
  "build_dirs": [
    "studio/dist",
    "web/.next/static"
  ],
  "build_files": 3,
  "exit_code": 1,
  "summary": {
    "critical": 8,
    "high": 5,
    "medium": 2,
    "low": 0,
    "info": 0
  },
  "findings": [
    {
      "rule_id": "KLC001",
      "severity": "critical",
      "message": "OpenAI API key in NEXT_PUBLIC_OPENAI_API_KEY: the public prefix makes the bundler inline it into the JavaScript every visitor downloads.",
      "file": "web/.env.local",
      "line": 6,
      "evidence": "NEXT_PUBLIC_OPENAI_API_KEY=sk-p**** (128 chars)",
      "heuristic": false,
      "extra": {
        "var": "NEXT_PUBLIC_OPENAI_API_KEY",
        "server_var": "OPENAI_API_KEY",
        "provider": "openai",
        "framework": "next"
      },
      "title": "Secret in a browser-exposed env var",
      "why": "Bundlers copy every variable with a public prefix (NEXT_PUBLIC_, VITE_, REACT_APP_, EXPO_PUBLIC_, PUBLIC_, NUXT_PUBLIC_) into the JavaScript sent to every visitor. A secret key there is public the moment you deploy: anyone can open DevTools, copy it and spend your credits or read your data. Bots scan deployed bundles for exactly these keys.",
      "fix": "1. Rotate the key now. Every build made with the old value contains it, and old\n   deploys and CDN caches keep serving it.\n   Where: platform.openai.com -> API keys -> revoke.\n2. Rename it without the public prefix so the bundler never inlines it:\n     NEXT_PUBLIC_OPENAI_API_KEY  ->  OPENAI_API_KEY\n   Set OPENAI_API_KEY in .env.local (git-ignored) and in your host's environment settings.\n3. Use it only in server code, and let the browser call your endpoint instead:\n   Next.js, app/api/ai/route.ts (runs only on the server; a \"use server\" action also works):\n     export async function POST(req: Request) {\n       // check the user's session and rate-limit here: this endpoint spends your money\n       const { prompt } = await req.json();\n       const r = await fetch(\"https://api.openai.com/v1/chat/completions\", {\n         method: \"POST\",\n         headers: { \"Content-Type\": \"application/json\", Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },\n         body: JSON.stringify({ /* model + validated prompt; never forward the raw body */ }),\n       });\n       return Response.json(await r.json(), { status: r.status });\n     }\n     browser:  await fetch(\"/api/ai\", { method: \"POST\", body: JSON.stringify({ prompt }) })"
    }
  ]
}
```

## Development

```bash
pip install -e ".[test]"
pytest
```

The repository never contains a real or real-looking secret: test and demo keys are random
strings assembled at run time from a fixed seed (`tests/conftest.py`,
`examples/make_demo.py`), and a test checks that no file in the repo matches any token
pattern.

## License

MIT, Copyright (c) 2026 Abheesht Tripathi. See [LICENSE](LICENSE).

---

Need help moving AI keys out of the browser before launch? abheeshttripathi890@gmail.com
