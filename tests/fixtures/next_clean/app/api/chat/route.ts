import OpenAI from "openai";

const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

export async function POST(req: Request) {
  const { prompt } = await req.json();
  const r = await openai.chat.completions.create({
    model: process.env.NEXT_PUBLIC_OPENAI_MODEL ?? "gpt-4o-mini",
    messages: [{ role: "user", content: String(prompt).slice(0, 4000) }],
  });
  return Response.json({ text: r.choices[0].message.content });
}
