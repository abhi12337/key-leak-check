"use client";
import { createClient } from "@supabase/supabase-js";
import { loadStripe } from "@stripe/stripe-js";
import { initializeApp } from "firebase/app";

// Publishable / public-by-design keys: fine in the browser.
const supabase = createClient(process.env.NEXT_PUBLIC_SUPABASE_URL!, process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY!);
const stripe = loadStripe(process.env.NEXT_PUBLIC_STRIPE_PUBLISHABLE_KEY!);
const app = initializeApp({ apiKey: process.env.NEXT_PUBLIC_FIREBASE_API_KEY, projectId: "demo" });
const razorpayKeyId = process.env.NEXT_PUBLIC_RAZORPAY_KEY_ID;

export default function Page() {
  async function ask() {
    const r = await fetch("/api/chat", { method: "POST", body: JSON.stringify({ prompt: "hi" }) });
    return r.json();
  }
  return <button onClick={ask}>Ask</button>;
}
