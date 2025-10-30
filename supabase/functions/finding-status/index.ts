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
  jsonResponse,
  errorResponse,
  buildCookie,
  COOKIE_OPTIONS,
  REFRESH_COOKIE_OPTIONS,
} from "../_shared/response.ts";

import {
  extractTokens,
  validateAccessToken,
  refreshSession,
} from "../_shared/auth.ts";

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  // Preflight
  if (req.method === "OPTIONS") return handlePreflight(origin);
  if (req.method !== "GET") {
    return errorResponse(
      "Method not allowed",
      "METHOD_NOT_ALLOWED",
      "Only GET requests are allowed",
      405,
      corsHeaders
    );
  }

  const url = new URL(req.url);
  const analysisId = url.searchParams.get("analysis_id");
  if (!analysisId) {
    return errorResponse(
      "Missing analysis_id",
      "MISSING_PARAM",
      "analysis_id is required",
      400,
      corsHeaders
    );
  }

  const env = detectEnvironment(origin);
  const useCookies = shouldUseCookies(origin);
  const includeTokens = shouldIncludeTokensInBody(origin);

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

    // Pegar tokens (cookie/headers)
    const tokens = extractTokens(req);
    if (!tokens) {
      return errorResponse(
        "Not authenticated",
        "NO_TOKEN",
        "Please login again",
        401,
        corsHeaders
      );
    }

    // Validar access; se inválido e houver refresh, tentar renovar
    let authResult = await validateAccessToken(tokens.accessToken);

    if (!authResult.authenticated && tokens.refreshToken) {
      authResult = await refreshSession(tokens.refreshToken);

      if (!authResult.authenticated) {
        return errorResponse(
          authResult.error || "Session expired",
          authResult.code || "TOKEN_EXPIRED",
          "Please login again",
          401,
          corsHeaders
        );
      }
    }

    // Se houve refresh, preparar Set-Cookie (PROD) e opcionalmente incluir no body (DEV)
    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.set("Content-Type", "application/json");

    const bodyExtras: Record<string, unknown> = {};

    if (authResult.refreshed) {
      if (useCookies) {
        const accessCookie = buildCookie(
          "sb-access-token",
          authResult.accessToken!,
          COOKIE_OPTIONS
        );
        const refreshCookie = buildCookie(
          "sb-refresh-token",
          authResult.refreshToken!,
          REFRESH_COOKIE_OPTIONS
        );
        responseHeaders.append("Set-Cookie", accessCookie);
        responseHeaders.append("Set-Cookie", refreshCookie);
      }

      if (includeTokens) {
        bodyExtras.access_token = authResult.accessToken;
        bodyExtras.refresh_token = authResult.refreshToken;
        bodyExtras.expires_at = authResult.expiresAt;
      }
    }

    // Client supabase autenticado via Authorization: Bearer
    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: {
        headers: {
          Authorization: `Bearer ${authResult.accessToken ?? tokens.accessToken}`,
        },
      },
    });

    // Buscar análise do próprio usuário (RLS garante o user_id)
    const { data: analysis, error: analysisErr } = await supabase
      .from("contract_analyses")
      .select("id, status, started_at, finished_at")
      .eq("id", analysisId)
      .single();

    if (analysisErr || !analysis) {
      return errorResponse(
        "Not found",
        "NOT_FOUND",
        "Analysis not found",
        404,
        responseHeaders
      );
    }

    // Contagem por risk
    const { data: counts, error: countErr } = await supabase
      .from("v_contract_findings_by_risk")
      .select("risk, total")
      .eq("analyses_id", analysisId)
      .order("total", { ascending: false });

    if (countErr) {
      return errorResponse(
        "Query error",
        "DB_ERROR",
        countErr.message,
        500,
        responseHeaders
      );
    }

    return new Response(
      JSON.stringify({
        success: true,
        analysis,
        counts: counts ?? [],
        ...bodyExtras,
      }),
      { status: 200, headers: responseHeaders }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.log("Internal sever error:", error);
    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      message,
      500,
      corsHeaders
    );
  }
});
