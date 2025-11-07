import { createClient } from "jsr:@supabase/supabase-js@2";
import {
  getCorsHeaders,
  handlePreflight,
  detectEnvironment,
  shouldUseCookies,
  shouldIncludeTokensInBody,
} from "../_shared/cors.ts";
import { jsonResponse, buildCookie } from "../_shared/response.ts";

/**
 * Aguarda trigger criar registro em public.users
 */
async function waitForUserProfile(
  supabase: any,
  userId: string,
  maxRetries = 10,
  delayMs = 150
) {
  for (let attempt = 1; attempt <= maxRetries; attempt++) {
    console.log(`[AUTH-SIGNUP] Polling profile: ${attempt}/${maxRetries}`);

    const { data, error } = await supabase
      .from("users")
      .select("role, plan, full_name")
      .eq("id", userId)
      .single();

    if (data) {
      console.log("[AUTH-SIGNUP] Profile found:", data);
      return data;
    }

    if (error) {
      console.log(`[AUTH-SIGNUP] Profile not ready: ${error.message}`);
    }

    // Aguarda antes da próxima tentativa
    if (attempt < maxRetries) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  console.warn("[AUTH-SIGNUP] Profile not found after all retries");
  return null;
}


Deno.serve(async (req) => {
  const origin = req.headers.get("Origin");

  console.log("auth-signup function initialized");
  console.log(`[AUTH-SIGNUP] Origin: ${origin}`);

  // ============================================
  // CORS PREFLIGHT
  // ============================================
  if (req.method === "OPTIONS") {
    return handlePreflight(origin);
  }

  // ============================================
  // VALIDAR MÉTODO
  // ============================================
  if (req.method !== "POST") {
    return jsonResponse(
      { error: "Method not allowed" },
      405,
      getCorsHeaders(origin)
    );
  }

  try {
    const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
    const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;
    const env = detectEnvironment(origin);
    const useCookies = shouldUseCookies(origin);
    const includeTokens = shouldIncludeTokensInBody(origin);

    console.log(`[AUTH-SIGNUP] Environment: ${env}`);
    console.log(`[AUTH-SIGNUP] Use cookies: ${useCookies}`);
    console.log(`[AUTH-SIGNUP] Include tokens in body: ${includeTokens}`);

    // ============================================
    // VALIDAR BODY
    // ============================================
    let body;
    try {
      body = await req.json();
    } catch (error) {
      return jsonResponse(
        { error: "Invalid JSON body" },
        400,
        getCorsHeaders(origin)
      );
    }

    const { email, password, full_name } = body ?? {};

    if (!email || !password || !full_name) {
      return jsonResponse(
        { error: "Email, password and full_name are required" },
        400,
        getCorsHeaders(origin)
      );
    }

    const cleanFullName = full_name.trim();

    console.log(`[AUTH-SIGNUP] Registering user: ${email}`);

    // ============================================
    // CRIAR CONTA NO SUPABASE AUTH
    // ============================================
    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    const { data, error } = await supabase.auth.signUp({
      email,
      password,
      options: {
        data: {
          full_name: cleanFullName,
        },
      },
    });

    if (error) {
      console.error("[AUTH-SIGNUP] Signup failed:", error.message);
      return jsonResponse(
        {
          error: "Failed to create account",
          code: "SIGNUP_FAILED",
          details: error.message,
        },
        400,
        getCorsHeaders(origin)
      );
    }

    // ============================================
    // VERIFICAR SE PRECISA CONFIRMAR EMAIL
    // ============================================
    if (!data.session || !data.user) {
      console.log("[AUTH-SIGNUP] Email confirmation required");
      return jsonResponse(
        {
          success: true,
          message: "Account created! Please check your email to confirm.",
          user: {
            id: data.user?.id,
            email: data.user?.email,
          },
          email_confirmation_required: true,
        },
        201,
        getCorsHeaders(origin)
      );
    }

    console.log(
      `[AUTH-SIGNUP]  User created: ${data.user.email} (ID: ${data.user.id})`
    );

    // ============================================
    // AGUARDAR TRIGGER CRIAR PERFIL
    // ============================================
    console.log("[AUTH-SIGNUP] Waiting for profile creation (trigger)...");
    const profile = await waitForUserProfile(supabase, data.user.id);

    // ============================================
    // PREPARAR DADOS DO USUÁRIO
    // ============================================
    const userResponse = {
      id: data.user.id,
      email: data.user.email,
      role: profile?.role || "user",
      plan: profile?.plan || "free",
      full_name: profile?.full_name || cleanFullName,
    };

    // ============================================
    // MODO PROD: RETORNAR COM COOKIES
    // ============================================
    if (useCookies) {
      console.log("[AUTH-SIGNUP] [PROD] Building cookies...");

      const accessCookie = buildCookie(
        "sb-access-token",
        data.session.access_token,
        3600 // 1 hora
      );

      const refreshCookie = buildCookie(
        "sb-refresh-token",
        data.session.refresh_token,
        604800 // 7 dias
      );

      const responseHeaders = new Headers(getCorsHeaders(origin));
      responseHeaders.append("Set-Cookie", accessCookie);
      responseHeaders.append("Set-Cookie", refreshCookie);

      console.log("[AUTH-SIGNUP] [PROD] Cookies added to headers");

      return new Response(
        JSON.stringify({
          success: true,
          user: userResponse,
          expires_at: data.session.expires_at,
        }),
        {
          status: 201,
          headers: responseHeaders,
        }
      );
    }

    // ============================================
    // MODO DEV: RETORNAR TOKENS NO BODY
    // ============================================
    console.log("[AUTH-SIGNUP] [DEV] Including tokens in body");

    return jsonResponse(
      {
        success: true,
        user: userResponse,
        access_token: data.session.access_token,
        refresh_token: data.session.refresh_token,
        expires_at: data.session.expires_at,
      },
      201,
      getCorsHeaders(origin)
    );
  } catch (error) {
    console.error("[AUTH-SIGNUP] Unexpected error:", error);
    return jsonResponse(
      {
        error: "Internal server error",
        code: "SIGNUP_ERROR",
        message: error instanceof Error ? error.message : "Unknown error",
      },
      500,
      getCorsHeaders(origin)
    );
  }
});
