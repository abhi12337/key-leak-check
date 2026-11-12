"use client";

export async function summarise(text: string) {
  const res = await fetch("https://api.anthropic.com/v1/messages", {
    method: "POST",
    headers: {
      "x-api-key": process.env.NEXT_PUBLIC_ANTHROPIC_API_KEY!,
      "anthropic-version": "2023-06-01",
      "content-type": "application/json",
    },
    body: JSON.stringify({ model: "claude-sonnet-4-5", max_tokens: 512, messages: [{ role: "user", content: text }] }),
  });
  return res.json();
}
