import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import {
  getCorsHeaders,
  handlePreflight,
  detectEnvironment,
  shouldUseCookies,
  shouldIncludeTokensInBody,
} from "../_shared/cors.ts";
import {
  errorResponse,
  buildCookie,
  COOKIE_OPTIONS,
  REFRESH_COOKIE_OPTIONS,
} from "../_shared/response.ts";
import { getUserProfile } from "../_shared/auth.ts";

console.log("auth-login function initialized");

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  // CORS Preflight
  if (req.method === "OPTIONS") {
    return handlePreflight(origin);
  }

  // Validar método
  if (req.method !== "POST") {
    return errorResponse(
      "Method not allowed",
      "METHOD_NOT_ALLOWED",
      "Only POST requests are allowed",
      405,
      corsHeaders
    );
  }

  // Detectar ambiente
  const env = detectEnvironment(origin);
  const useCookies = shouldUseCookies(origin);
  const includeTokens = shouldIncludeTokensInBody(origin);

  console.log(`[AUTH-LOGIN] Environment: ${env} (origin: ${origin})`);
  console.log(`[AUTH-LOGIN] Use cookies: ${useCookies}`);
  console.log(`[AUTH-LOGIN] Include tokens: ${includeTokens}`);

  try {
    // Validar variáveis de ambiente
    const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
    const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";

    if (!SUPABASE_URL || !SUPABASE_ANON_KEY) {
      return errorResponse(
        "Configuration error",
        "ENV_ERROR",
        "Missing Supabase configuration",
        500,
        corsHeaders
      );
    }

    // Ler body da requisição
    let body;
    try {
      body = await req.json();
    } catch {
      return errorResponse(
        "Invalid request",
        "INVALID_JSON",
        "Request body must be valid JSON",
        400,
        corsHeaders
      );
    }

    const { email, password } = body;

    // Validar campos obrigatórios
    if (!email || !password) {
      return errorResponse(
        "Missing credentials",
        "MISSING_FIELDS",
        "Email and password are required",
        400,
        corsHeaders
      );
    }

    // Criar cliente Supabase
    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    // Tentar fazer login
    console.log(`[AUTH-LOGIN] Login attempt: ${email}`);

    const { data, error } = await supabase.auth.signInWithPassword({
      email,
      password,
    });

    // Validar resposta
    if (error || !data.session || !data.user) {
      console.log(`[AUTH-LOGIN] Login failed: ${error?.message}`);
      return errorResponse(
        "Authentication failed",
        "INVALID_CREDENTIALS",
        error?.message || "Invalid email or password",
        401,
        corsHeaders
      );
    }

    console.log(`[AUTH-LOGIN] Login successful: ${data.user.email}`);

    // Buscar perfil do usuário
    const profile = await getUserProfile(
      data.user.id,
      data.user.email,
      data.session.access_token
    );

    if (!profile) {
      return errorResponse(
        "Profile not found",
        "PROFILE_ERROR",
        "User profile not found",
        404,
        corsHeaders
      );
    }

    // Preparar response headers
    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.set("Content-Type", "application/json");

    // Adicionar cookies SE for produção
    if (useCookies) {
      const accessCookie = buildCookie(
        "sb-access-token",
        data.session.access_token,
        COOKIE_OPTIONS
      );
      const refreshCookie = buildCookie(
        "sb-refresh-token",
        data.session.refresh_token,
        REFRESH_COOKIE_OPTIONS
      );

      responseHeaders.append("Set-Cookie", accessCookie);
      responseHeaders.append("Set-Cookie", refreshCookie);

      console.log(`[AUTH-LOGIN] [${env}] Cookies added to response`);
    }

    // Preparar response body
    const responseBody: Record<string, unknown> = {
      success: true,
      user: {
        id: data.user.id,
        email: data.user.email,
        ...profile,
      },
    };

    // Incluir tokens no body SE for desenvolvimento
    if (includeTokens) {
      responseBody.access_token = data.session.access_token;
      responseBody.refresh_token = data.session.refresh_token;
      responseBody.expires_at = data.session.expires_at;
      console.log(`[AUTH-LOGIN] [${env}] Tokens included in body`);
    } else {
      console.log(`[AUTH-LOGIN] [${env}] Tokens NOT in body (cookies only)`);
    }

    console.log(`[AUTH-LOGIN] Session created for: ${data.user.email}`);

    // Retornar resposta
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: responseHeaders,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[AUTH-LOGIN] Unhandled error:", message);

    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      message,
      500,
      corsHeaders
    );
  }
});
