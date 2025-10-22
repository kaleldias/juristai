import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { refreshSession, extractTokens } from "../_shared/auth.ts";
import {
  getCorsHeaders,
  handlePreflight,
  detectEnvironment,
  shouldUseCookies,
  shouldIncludeTokensInBody,
} from "../_shared/cors.ts";
import {
  jsonResponse,
  errorResponse,
  buildCookie,
  COOKIE_OPTIONS,
  REFRESH_COOKIE_OPTIONS,
} from "../_shared/response.ts";

console.log("auth-refresh function initialized");

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  // Cors Preflight
  if (req.method === "OPTIONS") {
    return handlePreflight(origin);
  }

  if (req.method !== "POST") {
    return errorResponse(
      "Method not allowed",
      "METHOD_NOT_ALLOWED",
      "Only POST request are allowed",
      405,
      corsHeaders
    );
  }

  // Detectar ambiente
  const env = detectEnvironment(origin);
  const useCookies = shouldUseCookies(origin);
  const includeTokens = shouldIncludeTokensInBody(origin);

  console.log(`[AUTH-REFRESH] Environment: ${env}`);

  // ====== LÓGICA DE NEGÓCIO =======
  try {
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

    // Extrai REFRESH TOKEN
    const tokens = extractTokens(req);
    let refreshToken = tokens?.refreshToken ?? null;

    if (refreshToken) {
      console.log(`[AUTH-REFRESH] Refresh token from cookie/header`);
    }

    if (!refreshToken && includeTokens) {
      try {
        const body = await req.json();
        refreshToken = body.refresh_token;

        if (refreshToken) {
          console.log(`[AUTH-REFRESH] Refresh token from body`);
        }
      } catch (error) {
        const message = error instanceof Error ? error.message : "Unknown";
        console.log(`[AUTH-REFRESH] Could not parse body: ${message}`);
      }
    }

    if (!refreshToken) {
      return errorResponse(
        "No refresh token",
        "NO_REFRESH_TOKEN",
        "Please login again",
        401,
        corsHeaders
      );
    }

    // ===== RENOVAR SESSÃO =====
    console.log(`[AUTH-REFRESH] Attempting to refresh session...`);

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    const { data, error } = await supabase.auth.refreshSession({
      refresh_token: refreshToken,
    });

    if (error || !data.session || !data.user) {
      console.log(`[AUTH-REFRESH] Refresh failed: ${error?.message}`);
      return errorResponse(
        "Session expired",
        "REFRESH_FAILED",
        error?.message || "Please login again",
        401,
        corsHeaders
      );
    }

    console.log(
      `[AUTH-REFRESH] Session refreshed successfully for: ${data.user.email}`
    );

    // ===== PREPARAR RESPOSTA =====
    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.set("Content-Type", "application/json");

    // Adicionar cookies se for PROD
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

      console.log(`[AUTH-REFRESH] [${env}] Cookies set`);
    }

    // Preparar response body
    const responseBody: Record<string, unknown> = {
      success: true,
      message: "Session refreshed successfully",
    };

    // Incluir tokens no body SE for DEV
    if (includeTokens) {
      responseBody.access_token = data.session.access_token;
      responseBody.refresh_token = data.session.refresh_token;
      responseBody.expires_at = data.session.expires_at;
      console.log(`[AUTH-REFRESH] [${env}] Tokens included in body`);
    } else {
      console.log(`[AUTH-REFRESH] [${env}] Tokens NOT in body (cookies only)`);
    }

    // Retornar resposta
    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: responseHeaders,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[AUTH-REFRESH] Unhandled error:", message);

    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      message,
      500,
      corsHeaders
    );
  }
});
