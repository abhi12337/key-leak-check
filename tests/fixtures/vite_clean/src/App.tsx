import { createClient } from "@supabase/supabase-js";

const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, import.meta.env.VITE_SUPABASE_ANON_KEY);

export async function ask(prompt: string) {
  // The browser only talks to our own endpoint; the key lives on the server.
  const r = await fetch("/api/ai", { method: "POST", body: JSON.stringify({ prompt }) });
  return r.json();
}
