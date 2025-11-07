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

  const { pathname, searchParams } = new URL(req.url);
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

  // paginação por página/limite (incremental)
  const limit = Math.max(1,Math.min(Number(searchParams.get("limit")) || 50, 200));
  const page = Math.max(1, Number(searchParams.get("page")) || 1);
  const offset = (page - 1) * limit;

  // filtros do schema real
  const risk = searchParams.get("risk") || undefined; // 'LOW' | 'MEDIUM' | 'HIGH'
  const type = searchParams.get("type") || undefined; // VARCHAR(200)
  const q = searchParams.get("q") || undefined; // busca em title/description/recommendation

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
    if (!tokens) {
      return errorResponse(
        "Not authenticated",
        "NO_TOKEN",
        "Please login again",
        401,
        corsHeaders
      );
    }

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

    // query com paginação por range (OFFSET/LIMIT) e count exato
    let query = supabase
      .from("contract_findings")
      .select(
        `
        id,
        analysis_id:analyses_id,
        user_id,
        type,
        risk,
        title,
        description,
        recommendation,
        source_span,
        extra,
        created_at
        `,
        { count: "exact" }
      )
      .eq("analyses_id", id)
      .order("created_at", { ascending: false })
      .range(offset, offset + limit - 1);

    if (risk) query = query.eq("risk", risk);
    if (type) query = query.eq("type", type);

    if (q) {
      // busca simples; considere índices trigram (pg_trgm) p/ performance
      query = query.or(
        `title.ilike.%${q}%,description.ilike.%${q}%,recommendation.ilike.%${q}%`
      );
    }

    const { data, error, count } = await query;
    if (error) {
      return errorResponse(
        "Query error",
        "DB_ERROR",
        error.message,
        500,
        responseHeaders
      );
    }

    const totalItems = count ?? null;
    const totalPages = totalItems ? Math.ceil(totalItems / limit) : null;
    const hasNext = totalPages ? page < totalPages : false;
    const hasPrev = page > 1;

    return new Response(
      JSON.stringify({
        success: true,
        items: data || [],
        pagination: { page, limit, totalItems, totalPages, hasNext, hasPrev },
        ...bodyExtras,
      }),
      { status: 200, headers: responseHeaders }
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      message,
      500,
      corsHeaders
    );
  }
});
