// Vercel serverless function: runs on the server, reads a non-public env var.
export default async function handler(req: any, res: any) {
  const r = await fetch("https://api.openai.com/v1/chat/completions", {
    method: "POST",
    headers: { "Content-Type": "application/json", Authorization: `Bearer ${process.env.OPENAI_API_KEY}` },
    body: JSON.stringify({ model: "gpt-4o-mini", messages: [{ role: "user", content: String(req.body.prompt) }] }),
  });
  res.status(r.status).json(await r.json());
}
