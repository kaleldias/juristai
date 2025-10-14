import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

console.log("auth-logout function initialized");

const ALLOWED_ORIGINS = [
  "https://7eb14f49-5c74-4713-9973-342719cde6fc.weweb-preview.io",
  "https://editor.weweb.io",
  "https://cdn.weweb.io",
];

/* prettier-ignore */
function getCorsHeaders(origin: string | null) { 
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin ?? "") ? (origin as string): ALLOWED_ORIGINS[0];
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

// Response Helper
function jsonResponse(body: unknown, status = 200, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(body), { status, headers });
}

function buildCookie(name: string, value: string, maxAge: number) {
  const parts: string[] = [
    `${name}=${value}`,
    `Max-Age=${maxAge}`,
    `Path=/`,
    `HttpOnly`,
    `Secure`,
    `SameSite=none`,
  ];

  return parts.join("; ");
}

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
      return jsonResponse({ error: "Missing Supabase environment variables" }, 500, corsHeaders);
    }

    // Pega access_token e refresh_token dos cookies
    const cookies = req.headers.get("Cookie") || "";
    const accessTokenMatch = cookies.match(/sb-access-token=([^;]+)/);
    const refreshTokenMatch = cookies.match(/sb-refresh-token=([^;]+)/);
    const accessToken = accessTokenMatch ? accessTokenMatch[1] : null;
    const refreshToken = refreshTokenMatch ? refreshTokenMatch[1] : null;

    console.log("Cookie access_token encontrado:", !!accessToken);
    console.log("Cookie refresh_token encontrado:", !!refreshToken);

    // Se tem tokens, tenta invalidar a sessão no Supabase
    if (accessToken && refreshToken) {
      const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

      // Define a sessão no SDK antes do signOut
      const { error: sessionError } = await supabase.auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });

      if (sessionError) {
        console.error("Erro ao definir sessão:", sessionError);
      } else {
        // Agora invalida a sessão
        const { error } = await supabase.auth.signOut({ scope: "local" });

        if (error) {
          console.error("Erro ao invalidar sessão no Supabase:", error);
        } else {
          console.log("Sucesso! Sessão invalidada no Supabase");
        }
      }
    }

    // Limpa os cookies (access_token e refresh_token)
    const clearAccessCookie = buildCookie("sb-access-token", "", 0);
    const clearRefreshCookie = buildCookie("sb-refresh-token", "", 0);

    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.append("Set-Cookie", clearAccessCookie);
    responseHeaders.append("Set-Cookie", clearRefreshCookie);

    /* prettier-ignore */
    return jsonResponse({
        success: true,
        message: "Logout realizado com sucesso!",
      }, 200, responseHeaders);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Unhandled error in auth-logout:", message);
    /* prettier-ignore */
    return jsonResponse({ error: "Internal server error", details: message }, 500, corsHeaders);
  }
});
