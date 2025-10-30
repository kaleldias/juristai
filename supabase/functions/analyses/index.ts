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

  const url = new URL(req.url);
  const limit = Math.max(
    1,
    Math.min(Number(url.searchParams.get("limit")) || 20, 50)
  );
  const page = Math.max(1, Number(url.searchParams.get("page")) || 1); 
  const status = url.searchParams.get("status") || undefined;
  const q = url.searchParams.get("q") || undefined;

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

    // cálculo de offset
    const offset = (page - 1) * limit;

    let query = supabase
      .from("contract_analyses")
      .select(
        `
        id, status, started_at, finished_at, contract_file_id, summary->>risk_score,
        contract_files:contract_file_id (id, title, mime_type)
      `,
        { count: "exact" } // permite total de registros
      )
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1); // paginação com OFFSET/LIMIT

    if (status) query = query.eq("status", status);
    if (q) query = query.ilike("contract_files.title", `%${q}%`);

    const { data, error, count } = await query;
    if (error)
      return errorResponse(
        "Query error",
        "DB_ERROR",
        error.message,
        500,
        responseHeaders
      );

    // total de páginas
    const totalPages = count ? Math.ceil(count / limit) : null;
    const hasNext = totalPages ? page < totalPages : false;
    const hasPrev = page > 1;

    return new Response(
      JSON.stringify({
        success: true,
        items: data || [],
        pagination: {
          page,
          limit,
          total: count,
          totalPages,
          hasNext,
          hasPrev,
        },
        ...bodyExtras,
      }),
      { status: 200, headers: responseHeaders }
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
