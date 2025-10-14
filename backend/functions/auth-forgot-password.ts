import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

console.log("auth-forgot-password function initialized");

const ALLOWED_ORIGINS = [
  "https://7eb14f49-5c74-4713-9973-342719cde6fc.weweb-preview.io",
  "https://editor.weweb.io",
  "https://cdn.weweb.io",
];

/* prettier-ignore */
function getCorsHeaders(origin: string | null) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin ?? "") ? (origin as string) : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Vary": "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "authorization, apikey, x-client-info, x-supabase-auth, x-requested-with, content-type",
    "Access-Control-Expose-Headers": "authorization, apikey",
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "application/json"
  };
}

function jsonResponse(body: unknown, status = 200, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(body), { status, headers });
}

//Handler
Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405, corsHeaders);
  }

  try {
    const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
    const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
      /* prettier-ignore */
      return jsonResponse({ error: "Missing supabase environment variables" }, 500, corsHeaders);
    }

    const { email } = await req.json();

    if (!email) {
      return jsonResponse({ error: "Email é obrigatório!" }, 400, corsHeaders);
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo:
        "https://7eb14f49-5c74-4713-9973-342719cde6fc.weweb-preview.io/reset-password",
    });

    if (error) {
      console.error("Error sending reset email:", error.message);
      return jsonResponse(
        { error: "Erro ao enviar email de recuperação" },
        400,
        corsHeaders
      );
    }

    return jsonResponse(
      { success: true, message: "Link enviado! Cheque seu email" }, 200, corsHeaders
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Unhandled error in auth-forgot-password:", message);
    /* prettier-ignore */
    return jsonResponse({ error: 'Internal server error', details: message }, 500, corsHeaders)
  }
});
