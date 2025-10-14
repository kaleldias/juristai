import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

console.log("auth-reset-password function initialized");

const ALLOWED_ORIGINS = [
  "https://7eb14f49-5c74-4713-9973-342719cde6fc.weweb-preview.io",
  "https://editor.weweb.io",
  "https://cdn.weweb.io",
];

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "none" as const,
  path: "/",
  maxAge: 3600, // 1 hora
};

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

/* prettier-ignore */
function buildCookie(name: string, value: string, options: typeof COOKIE_OPTIONS): string {
  const parts: string[] = [
    `${name}=${value}`,
    `Max-Age=${options.maxAge}`,
    `Path=${options.path}`,
  ];
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

    const { accessToken, refreshToken, newPassword } = await req.json();

    /* prettier-ignore */
    if (!accessToken || !refreshToken || !newPassword) {
      return jsonResponse({
        error:"Token de acesso, token de atualização e nova senha são obrigatórios!",
      }, 400, corsHeaders);
    }

    if (newPassword.length < 6) {
      /* prettier-ignore */
      return jsonResponse({ error: "Senha deve ter no mínimo 6 caracteres!" }, 400, corsHeaders);
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    // Estabelece a sessão com os tokens de recuperação
    const { data: sessionData, error: sessionError } =
      await supabase.auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });

    if (sessionError || !sessionData.session) {
      console.error("Error setting session:", sessionError?.message);
      /* prettier-ignore */
      return jsonResponse({ error: "Token inválido ou expirado" }, 400, corsHeaders);
    }

    console.log("Session established, updating password");

    // Atualiza senha
    const { data, error } = await supabase.auth.updateUser({
      password: newPassword,
    });

    /* prettier-ignore */
    if (error || !data.user) {
      console.error("Error updating password:", error?.message);
      return jsonResponse({ error: "Erro ao atualizar senha", details: error.message }, 400, corsHeaders);
    }

    console.log("Password updated successfully for user, creating new session");

    // Cria nova sessão com a senha atualizada
    /* prettier-ignore */
    const { data: newSession, error: newSessionError } = await supabase.auth.refreshSession();

    if (newSessionError || !newSession.session) {
      console.error("Error creating new session:", newSessionError?.message);
      /* prettier-ignore */
      return jsonResponse({
        success: true,
        message: "Senha atualizada! Faça login novamente.",
        requires_login: true
      }, 200, corsHeaders);
    }

    // Cria cookies com os novos tokens
    /* prettier-ignore */
    const accessCookie = buildCookie('sb-access-token', newSession.session.access_token, COOKIE_OPTIONS);
    const refhresCookie = buildCookie(
      "sb-refresh-token",
      newSession.session.refresh_token,
      { ...COOKIE_OPTIONS, maxAge: 604800 }
    );

    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.append("Set-Cookie", accessCookie);
    responseHeaders.append("Set-Cookie", refhresCookie);

    console.log("Password reset complete, user logged in:", data.user.email);

    return jsonResponse(
      {
        success: true,
        message: "Senha atualizada com sucesso! Redirecionando...",
        user: {
          id: data.user.id,
          email: data.user.email,
        },
      },
      200,
      responseHeaders
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Unhandled error in auth-reset-password:", message);
    /* prettier-ignore */
    return jsonResponse({ error: 'Internal server error', details: message }, 500, corsHeaders)
  }
});
