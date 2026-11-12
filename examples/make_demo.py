"""Generate a deliberately leaky demo project to try key-leak-check on.

    python examples/make_demo.py demo-ai-app
    key-leak-check scan demo-ai-app

It writes two small AI apps: `web/` (Next.js) and `studio/` (a Vite + Gemini app in the
style of an AI Studio export), each with the mistakes this tool looks for, plus some
correct code (a server route handler, publishable keys) that must NOT be reported.

Every key is random text assembled at runtime from a fixed seed, so this repository never
contains a secret-shaped string. None of them work anywhere.
"""

from __future__ import annotations

import base64
import json
import random
import string
import sys
from pathlib import Path

RNG = random.Random(20261111)
ALNUM = string.ascii_letters + string.digits


def rand(n: int, alphabet: str = ALNUM) -> str:
    return "".join(RNG.choice(alphabet) for _ in range(n))


def b64(obj) -> str:
    raw = obj if isinstance(obj, bytes) else json.dumps(obj, separators=(",", ":")).encode()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")


def jwt(role: str) -> str:
    payload = {"iss": "supabase", "ref": rand(20, string.ascii_lowercase), "role": role,
               "iat": 1760000000, "exp": 2075000000}
    return f"{b64({'alg': 'HS256', 'typ': 'JWT'})}.{b64(payload)}.{rand(43, ALNUM + '_-')}"


OPENAI = "sk-" + "proj-" + rand(120, ALNUM + "_-")
ANTHROPIC = "sk-" + "ant-" + "api03-" + rand(93, ALNUM + "_-")
GEMINI = "AI" + "za" + "Sy" + rand(33, ALNUM + "_-")
STRIPE_SECRET = "sk_" + "live_" + rand(99)
STRIPE_PUBLISHABLE = "pk_" + "live_" + rand(99)
RESEND = "re" + "_" + rand(8) + "_" + rand(24)
SERVICE_ROLE = jwt("service" + "_role")
ANON = jwt("anon")

FILES = {
    # ------------------------------------------------------------ Next.js app
    "web/package.json": json.dumps({"name": "web", "private": True,
                                    "dependencies": {"next": "15.5.4", "openai": "5.23.0", "stripe": "18.5.0"}},
                                   indent=2) + "\n",
    "web/.gitignore": "node_modules/\n.next/\n",
    "web/.env.local": (
        f"NEXT_PUBLIC_SUPABASE_URL=https://{rand(20, string.ascii_lowercase)}.supabase.co\n"
        f"NEXT_PUBLIC_SUPABASE_ANON_KEY={ANON}\n"
        f"NEXT_PUBLIC_SUPABASE_SERVICE_ROLE_KEY={SERVICE_ROLE}\n"
        f"NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY={STRIPE_PUBLISHABLE}\n"
        f"STRIPE_SECRET_KEY={STRIPE_SECRET}\n"
        f"NEXT_PUBLIC_OPENAI_API_KEY={OPENAI}\n"
    ),
    "web/app/chat/page.tsx": """\
"use client";
import { useState } from "react";
import OpenAI from "openai";

const openai = new OpenAI({
  apiKey: process.env.NEXT_PUBLIC_OPENAI_API_KEY,
  dangerouslyAllowBrowser: true,
});

export default function Chat() {
  const [answer, setAnswer] = useState("");
  async function ask(prompt: string) {
    const r = await openai.chat.completions.create({
      model: "gpt-4o-mini",
      messages: [{ role: "user", content: prompt }],
    });
    setAnswer(r.choices[0].message.content ?? "");
  }
  return <button onClick={() => ask("hello")}>{answer || "Ask"}</button>;
}
""",
    "web/app/api/checkout/route.ts": """\
import Stripe from "stripe";

// Correct: server-only route handler, secret read from a non-public env var.
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!);

export async function POST(req: Request) {
  const { priceId } = await req.json();
  const session = await stripe.checkout.sessions.create({
    mode: "subscription",
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: "https://example.com/ok",
  });
  return Response.json({ url: session.url });
}
""",
    "web/lib/summarise.ts": f"""\
import Anthropic from "@anthropic-ai/sdk";

const ANTHROPIC_KEY = "{ANTHROPIC}";

export const anthropic = new Anthropic({{ apiKey: ANTHROPIC_KEY }});
""",
    "web/.next/static/chunks/app/chat/page-8f3a21c9.js":
        "(self.webpackChunk_N_E=self.webpackChunk_N_E||[]).push([[931],{4211:function(e,t,n){"
        f'let a=new o.ZP({{apiKey:"{OPENAI}",dangerouslyAllowBrowser:!0}});'
        "}}]);\n",
    # ------------------------------------------------------------ Vite + Gemini app
    "studio/package.json": json.dumps({"name": "studio", "private": True, "type": "module",
                                       "dependencies": {"@google/genai": "1.21.0", "react": "19.1.1"},
                                       "devDependencies": {"vite": "7.1.7"}}, indent=2) + "\n",
    "studio/.gitignore": "node_modules\ndist\n.env*\n!.env.example\n",
    "studio/.env": f"GEMINI_API_KEY={GEMINI}\n",
    "studio/.env.example": f"GEMINI_API_KEY=your-gemini-key\nVITE_GROQ_API_KEY=\nRESEND_API_KEY={RESEND}\n",
    "studio/vite.config.ts": """\
import { defineConfig, loadEnv } from "vite";
import react from "@vitejs/plugin-react";

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, ".", "");
  return {
    plugins: [react()],
    define: {
      "process.env.GEMINI_API_KEY": JSON.stringify(env.GEMINI_API_KEY),
    },
    build: { sourcemap: true },
  };
});
""",
    "studio/services/geminiService.ts": """\
import { GoogleGenAI } from "@google/genai";

const ai = new GoogleGenAI({ apiKey: process.env.GEMINI_API_KEY });

export async function describe(text: string) {
  const res = await ai.models.generateContent({ model: "gemini-2.5-flash", contents: text });
  return res.text;
}
""",
    "studio/src/lib/groq.ts": """\
export async function fastAnswer(prompt: string) {
  const r = await fetch("https://api.groq.com/openai/v1/chat/completions", {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${import.meta.env.VITE_GROQ_API_KEY}`,
    },
    body: JSON.stringify({ model: "llama-3.3-70b-versatile", messages: [{ role: "user", content: prompt }] }),
  });
  return (await r.json()).choices[0].message.content;
}
""",
    "studio/dist/index.html": '<!doctype html><html><head><script type="module" src="/assets/index-4f9a1c.js">'
                              "</script></head><body><div id=\"root\"></div></body></html>\n",
    "studio/dist/assets/index-4f9a1c.js":
        'const Bx="https://generativelanguage.googleapis.com";'
        f'var Qa=new Ee({{apiKey:"{GEMINI}"}});'
        "export{Qa as a};\n//# sourceMappingURL=index-4f9a1c.js.map\n",
    "studio/dist/assets/index-4f9a1c.js.map": json.dumps({"version": 3, "sources": ["../../services/geminiService.ts"],
                                                          "mappings": "AAAA"}) + "\n",
}


def main(dest: str) -> None:
    root = Path(dest)
    for rel, content in FILES.items():
        p = root / rel
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(content, encoding="utf-8", newline="\n")
    print(f"Demo project written to {root}. Now run:  key-leak-check scan {root}")


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "demo-ai-app")
