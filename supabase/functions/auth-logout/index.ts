import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import {
  getCorsHeaders,
  handlePreflight,
  detectEnvironment,
  shouldUseCookies,
} from "../_shared/cors.ts";
import {
  errorResponse,
  buildCookie,
  COOKIE_OPTIONS,
  REFRESH_COOKIE_OPTIONS,
} from "../_shared/response.ts";
import { extractTokens, validateAccessToken } from "../_shared/auth.ts";

console.log("auth-logout function initialized");

const CLEAR_ACCESS_COOKIE = { ...COOKIE_OPTIONS, maxAge: 0 };
const CLEAR_REFRESH_COOKIE = { ...REFRESH_COOKIE_OPTIONS, maxAge: 0 };

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  const method = req.method?.toUpperCase?.() ?? req.method ?? "UNKNOWN";

  console.log(`[AUTH-LOGOUT] Origin: ${origin}`);
  console.log(`[AUTH-LOGOUT] Method: ${method}`);

  if (method === "OPTIONS") {
    return handlePreflight(origin);
  }

  if (method !== "POST" && method !== "DELETE") {
    return errorResponse(
      "Method not allowed",
      "METHOD_NOT_ALLOWED",
      "Use POST or DELETE for logout",
      405,
      corsHeaders
    );
  }

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

    const useCookies = shouldUseCookies(origin);
    const env = detectEnvironment(origin);

    console.log(`[AUTH-LOGOUT] Environment: ${env}`);
    console.log(`[AUTH-LOGOUT] Use cookies: ${useCookies}`);

    const tokens = extractTokens(req);

    if (!tokens?.accessToken) {
      console.log("[AUTH-LOGOUT] No access token provided");
      return errorResponse(
        "No active session",
        "NO_SESSION",
        "User is not logged in",
        401,
        corsHeaders
      );
    }

    console.log("[AUTH-LOGOUT] Validating access token...");
    const authResult = await validateAccessToken(tokens.accessToken);

    if (!authResult.authenticated || !authResult.user) {
      console.log(
        `[AUTH-LOGOUT] Invalid token: ${authResult.error || "unknown error"}`
      );
      return errorResponse(
        "Invalid or expired token",
        authResult.code || "INVALID_TOKEN",
        authResult.error || "Access token invalid or expired",
        401,
        corsHeaders
      );
    }

    console.log(
      `[AUTH-LOGOUT] Signing out user: ${authResult.user.email} (ID: ${authResult.user.id})`
    );

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: {
        headers: {
          Authorization: `Bearer ${tokens.accessToken}`,
        },
      },
    });

    const { error } = await supabase.auth.signOut({ scope: "global" });

    if (error) {
      console.error("[AUTH-LOGOUT] Supabase signOut error:", error.message);
      return errorResponse(
        "Failed to invalidate session",
        "LOGOUT_FAILED",
        error.message,
        500,
        corsHeaders
      );
    }

    console.log("[AUTH-LOGOUT] Session invalidated successfully");

    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.set("Content-Type", "application/json");

    if (useCookies) {
      console.log("[AUTH-LOGOUT] Clearing cookies for PROD environment");
      const clearAccess = buildCookie(
        "sb-access-token",
        "",
        CLEAR_ACCESS_COOKIE
      );
      const clearRefresh = buildCookie(
        "sb-refresh-token",
        "",
        CLEAR_REFRESH_COOKIE
      );

      responseHeaders.append("Set-Cookie", clearAccess);
      responseHeaders.append("Set-Cookie", clearRefresh);
    }

    return new Response(
      JSON.stringify({
        success: true,
        message: "Logged out successfully",
        user: {
          id: authResult.user.id,
          email: authResult.user.email,
        },
      }),
      {
        status: 200,
        headers: responseHeaders,
      }
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[AUTH-LOGOUT] Unexpected error:", message);

    return errorResponse(
      "Logout failed",
      "LOGOUT_ERROR",
      message,
      500,
      corsHeaders
    );
  }
});
