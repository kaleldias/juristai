import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

console.log("auth-me function initialized");

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
    "Access-Control-Allow-Methods": "GET, OPTIONS",
    "Access-Control-Allow-Headers":
      "authorization, apikey, x-client-info, x-supabase-auth, x-requested-with, content-type",
    "Access-Control-Expose-Headers": "authorization, apikey",
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "application/json"
  };
}

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "none" as const,
  path: "/",
  maxAge: 3600, // 1 hora
};

function jsonResponse(body: unknown, status = 200, headers: HeadersInit = {}) {
  return new Response(JSON.stringify(body), { status, headers });
}

/* prettier-ignore */
function buildCookie(name: string, value: string, options: typeof COOKIE_OPTIONS): string {
  const parts: string[] = [`${name}=${value}`, `Max-Age=${options.maxAge}`, `Path=${options.path}`];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);

  return parts.join("; ");
}

//Handler
Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== "GET") {
    return jsonResponse({ error: "Method not allowed" }, 405, corsHeaders);
  }

  try {
    const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
    const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
      /* prettier-ignore */
      return jsonResponse({ error: "Missing supabase environment variables" }, 500, corsHeaders);
    }

    // Lê o cookies do header
    const cookieHeader = req.headers.get("Cookie");
    const cookies: Record<string, string> = {};

    if (!cookieHeader) {
      return jsonResponse(
        {
          error: "Not authenticated",
          code: "NO_TOKEN",
          message: "Please login again",
        },
        401,
        corsHeaders
      );
    }

    cookieHeader.split("; ").forEach((cookie) => {
      const [name, ...rest] = cookie.split("=");
      if (name) {
        cookies[name] = rest.join("=");
      }
    });

    const accessToken = cookies["sb-access-token"];
    const refreshToken = cookies["sb-refresh-token"];

    // Caso nenhum token presente
    if (!accessToken) {
      /* prettier-ignore */
      return jsonResponse({error: "Not authenticated", code: "NO_TOKEN"}, 401, corsHeaders)
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    // Valida o access token
    /* prettier-ignore */
    const { data: { user }, error } = await supabase.auth.getUser(accessToken);

    // Token inválido/expirado
    if (error || !user) {
      // Tenta refresh se tiver refresh token
      if (refreshToken) {
        const { data: refreshData, error: refreshError } =
          await supabase.auth.refreshSession({ refresh_token: refreshToken });

        if (refreshError || !refreshData.session) {
          /* prettier-ignore */
          // Refresh falhou - sessão realmente expirou
          return jsonResponse({ error: "Session expired", code: "TOKEN_EXPIRED" }, 401, corsHeaders);
        }

        /* prettier-ignore */
        // Refresh funcionou - atualiza cookies e retorna usuário
        const newAccessCookie =  buildCookie('sb-access-token', refreshData.session.access_token, COOKIE_OPTIONS);
        const newRefreshCookie = buildCookie(
          "sb-refresh-token",
          refreshData.session.refresh_token,
          { ...COOKIE_OPTIONS, maxAge: 604800 }
        );

        // Busca dados do usuário
        const { data: profile } = await supabase
          .from("users")
          .select("role, plan, full_name")
          .eq("id", refreshData.user.id)
          .single();

        const responseHeaders = new Headers(corsHeaders);
        responseHeaders.append("Set-Cookie", newAccessCookie);
        responseHeaders.append("Set-Cookie", newRefreshCookie);

        return jsonResponse(
          {
            success: true,
            user: {
              id: refreshData.user.id,
              email: refreshData.user.email,
              role: profile?.role,
              plan: profile?.plan,
              full_name: profile?.full_name,
            },
            expires_at: refreshData.session.expires_at,
          },
          200,
          responseHeaders
        );
      }

      // Não tem refresh token - token inválido sem possibilidade de renovar
      /* prettier-ignore */
      return jsonResponse({ error: "Invalid token", code:'INVALID_TOKEN', message: 'Please login again' }, 401, corsHeaders);
    }

    const authenticatedSupabase = createClient(
      SUPABASE_URL,
      SUPABASE_ANON_KEY,
      {
        global: {
          headers: {
            Authorization: `Bearer ${accessToken}`,
          },
        },
      }
    );

    const { data: profile } = await authenticatedSupabase
      .from("users")
      .select("role, plan, full_name")
      .eq("id", user.id)
      .single();

    /* prettier-ignore  */
    return jsonResponse({
      success: true,
      user: {
        id: user.id,
        email: user.email,
        role: profile?.role,
        plan: profile?.plan,
        full_name: profile?.full_name,
      }
    }, 200, corsHeaders);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Unhandled error in auth-me:", message);
    /* prettier-ignore */
    return jsonResponse({ error: 'Internal server error', details: message }, 500, corsHeaders)
  }
});
