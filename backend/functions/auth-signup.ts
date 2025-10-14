import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

console.log("auth-signup function initialized");

const ALLOWED_ORIGINS = [
  "https://7eb14f49-5c74-4713-9973-342719cde6fc.weweb-preview.io",
  "https://editor.weweb.io",
  "https://cdn.weweb.io",
];

function getCorsHeaders(origin: string | null) {
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin ?? "")
    ? (origin as string)
    : ALLOWED_ORIGINS[0];
  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    Vary: "Origin",
    "Access-Control-Allow-Methods": "POST, OPTIONS",
    "Access-Control-Allow-Headers":
      "authorization, apikey, x-client-info, x-supabase-auth, x-requested-with, content-type",
    "Access-Control-Expose-Headers": "authorization, apikey",
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "application/json",
  };
}

const COOKIE_OPTIONS = {
  httpOnly: true,
  secure: true,
  sameSite: "none" as const,
  path: "/",
  maxAge: 3600, // 1 hora
};

/* prettier-ignore */
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

/* prettir-ignore */
async function waitForUserProfile(
  supabase: any,
  userId: string,
  maxRetries = 10,
  delayMs = 150
): Promise<any> {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    console.log(`Tentativa: ${attempt}/${maxRetries} de buscar profile...`);

    const { data, error } = await supabase
      .from("users")
      .select("role, plan, full_name")
      .eq("id", userId)
      .single();

    if (data) {
      console.log("Profile econtrado", data);
      return data;
    }

    if (error) {
      console.log("Erro na busca", error.message);
    }

    // Aguarda antes da próxima tentativa
    if (attempt < maxRetries) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  console.warn("Porfile não encontrado após todas as tentativas");
  return null;
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

    /* prettier-ignore */
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
      return jsonResponse({ error: "Missing supabase environment variables" }, 500, corsHeaders);
    }

    // Parse body
    let body: any;
    try {
      body = await req.json();
    } catch (error) {
      /* prettier-ignore */
      return jsonResponse({ error: "Invalid JSON body" }, 400, corsHeaders);
    }

    const { email, password, full_name } = body ?? {};

    if (!email || !password || !full_name) {
      return jsonResponse(
        { error: "Email, Senha e Nome Completo são obrigatórios" },
        400,
        corsHeaders
      );
    }

    const cleanFullName = full_name.trim();

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    // Signup -  Cria usuário em auth.users
    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: { full_name: cleanFullName },
      },
    });

    if (error) {
      /* prettier-ignore */
      return jsonResponse({ error: "Falha ao criar conta", details: error.message }, 400, corsHeaders);
    }

    if (!data.session || !data.user) {
      // Se Email confirmation habilitado - não cria sessão imediatamente
      return jsonResponse(
        {
          success: true,
          message: "Conta criada! Verifique seu email para confirmar.",
          user: { id: data.user?.id, email: data.user?.email },
        },
        201,
        corsHeaders
      );
    }

    // Aguardar trigger criar o registro em public.users
    console.log("Aguardando trigger criar registro em public.users...");
    const profile = await waitForUserProfile(supabase, data.user.id);

    const accessCookie = buildCookie(
      "sb-access-token",
      data.session.access_token,
      COOKIE_OPTIONS
    );
    const refreshCookie = buildCookie(
      "sb-refresh-token",
      data.session.refresh_token,
      {
        ...COOKIE_OPTIONS,
        maxAge: 604800, // 7 dias
      }
    );

    // Retorna múltiplos cookies
    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.append("Set-Cookie", accessCookie);
    responseHeaders.append("Set-Cookie", refreshCookie);

    return new Response(
      JSON.stringify({
        success: true,
        user: {
          id: data.user.id,
          email: data.user.email,
          role: profile?.role,
          plan: profile?.plan,
          full_name: profile?.full_name,
        },
        expires_at: data.session.expires_at,
      }),
      {
        status: 201,
        headers: responseHeaders,
      }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("Unhandled error in auth-signup:", message);

    /* prettier-ignore */
    return jsonResponse({ error: "Internal server error", details: message }, 500, corsHeaders);
  }
});
