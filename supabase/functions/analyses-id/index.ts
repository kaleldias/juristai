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

  // /functions/v1/analyses-id/<id>
  const { pathname } = new URL(req.url);
  const id = pathname.split("/").pop();
  if (!id) {
    return errorResponse(
      "Missing id",
      "MISSING_PARAM",
      "id is required",
      400,
      corsHeaders
    );
  }

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

    const tokens = extractTokens(req);
    if (!tokens)
      return errorResponse(
        "Not authenticated",
        "NO_TOKEN",
        "Please login again",
        401,
        corsHeaders
      );

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

    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.set("Content-Type", "application/json");
    const bodyExtras: Record<string, unknown> = {};

    if (authResult.refreshed) {
      if (useCookies) {
        responseHeaders.append(
          "Set-Cookie",
          buildCookie(
            "sb-access-token",
            authResult.accessToken!,
            COOKIE_OPTIONS
          )
        );
        responseHeaders.append(
          "Set-Cookie",
          buildCookie(
            "sb-refresh-token",
            authResult.refreshToken!,
            REFRESH_COOKIE_OPTIONS
          )
        );
      }

      if (includeTokens) {
        bodyExtras.access_token = authResult.accessToken;
        bodyExtras.refresh_token = authResult.refreshToken;
        bodyExtras.expires_at = authResult.expiresAt;
      }
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: {
        headers: {
          Authorization: `Bearer ${authResult.accessToken ?? tokens.accessToken}`,
        },
      },
    });

    // Detalhe da análise + arquivo relacionado
    const { data, error } = await supabase
      .from("contract_analyses")
      .select(
        `
        id, status, started_at, finished_at,
        contract_file_id,
        contract_files:contract_file_id (id, title, storage_bucket, storage_path, mime_type)
      `
      )
      .eq("id", id)
      .single();

    if (error || !data) {
      return errorResponse(
        "Not found",
        "NOT_FOUND",
        "Analysis not found",
        404,
        responseHeaders
      );
    }

    return new Response(
      JSON.stringify({ success: true, analysis: data, ...bodyExtras }), {
        status: 200,
        headers: responseHeaders,
      }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      message,
      500,
      corsHeaders
    );
  }
});
