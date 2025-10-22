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
import type { ResetPasswordPayload } from "../_shared/types.ts";

console.log("auth-reset-password function initialized");

function getToken(
  payload: ResetPasswordPayload,
  keyA: keyof ResetPasswordPayload,
  keyB: keyof ResetPasswordPayload
): string | null {
  const valueA = payload[keyA];
  const valueB = payload[keyB];
  //prettier-ignore
  const value = typeof valueA === "string" ? valueA : typeof valueB === "string" ? valueB : null;

  if (!value) return null;
  const trimmed = value.trim();
  return trimmed.length ? trimmed : null;
}

function getNewPassword(payload: ResetPasswordPayload): string | null {
  const candidates: (keyof ResetPasswordPayload)[] = [
    "new_password",
    "newPassword",
    "password",
  ];

  for (const candidate of candidates) {
    const value = payload[candidate];
    if (typeof value === "string") {
      const trimmed = value.trim();
      if (trimmed.length) {
        return trimmed;
      }
    }
  }

  return null;
}

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  console.log(`[AUTH-RESET] Origin: ${origin}`);

  if (req.method === "OPTIONS") {
    return handlePreflight(origin);
  }

  if (req.method !== "POST") {
    return errorResponse(
      "Method not allowed",
      "METHOD_NOT_ALLOWED",
      "Only POST requests are allowed",
      405,
      corsHeaders
    );
  }

  const env = detectEnvironment(origin);
  const useCookies = shouldUseCookies(origin);
  const includeTokens = shouldIncludeTokensInBody(origin);

  console.log(`[AUTH-RESET] Environment: ${env}`);
  console.log(`[AUTH-RESET] Use cookies: ${useCookies}`);
  console.log(`[AUTH-RESET] Include tokens in body: ${includeTokens}`);

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

    let body: unknown;
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

    const payload = (body ?? {}) as ResetPasswordPayload;

    const accessToken = getToken(payload, "access_token", "accessToken");
    const refreshToken = getToken(payload, "refresh_token", "refreshToken");
    const newPassword = getNewPassword(payload);

    if (!accessToken || !refreshToken || !newPassword) {
      return errorResponse(
        "Missing fields",
        "MISSING_FIELDS",
        "Access token, refresh token and new password are required",
        400,
        corsHeaders
      );
    }

    if (newPassword.length < 6) {
      return errorResponse(
        "Invalid password",
        "WEAK_PASSWORD",
        "Password must have at least 6 characters",
        400,
        corsHeaders
      );
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

    console.log("[AUTH-RESET] Setting session with recovery tokens...");

    const { data: sessionData, error: sessionError } =
      await supabase.auth.setSession({
        access_token: accessToken,
        refresh_token: refreshToken,
      });

    if (sessionError || !sessionData.session) {
      console.error("[AUTH-RESET] setSession error:", sessionError?.message);
      return errorResponse(
        "Invalid or expired token",
        "INVALID_TOKEN",
        sessionError?.message || "Reset token is invalid or expired",
        400,
        corsHeaders
      );
    }

    console.log("[AUTH-RESET] Session established. Updating password...");
    const { data: updateData, error: updateError } =
      await supabase.auth.updateUser({
        password: newPassword,
      });

    if (updateError || !updateData.user) {
      console.error("[AUTH-RESET] updateUser error:", updateError?.message);
      return errorResponse(
        "Failed to update password",
        "UPDATE_FAILED",
        updateError?.message || "Unable to update password",
        400,
        corsHeaders
      );
    }

    console.log("[AUTH-RESET] Password updated. Refreshing session...");
    const { data: refreshedData, error: refreshError } =
      await supabase.auth.refreshSession();

    if (refreshError || !refreshedData.session) {
      console.warn(
        "[AUTH-RESET] refreshSession failed:",
        refreshError?.message
      );
      return jsonResponse(
        {
          success: true,
          message: "Password updated. Please log in again.",
          requires_login: true,
        },
        200,
        corsHeaders
      );
    }

    const responseHeaders = new Headers(corsHeaders);
    responseHeaders.set("Content-Type", "application/json");

    const responseBody: Record<string, unknown> = {
      success: true,
      message: "Password updated successfully.",
      requires_login: false,
      user: {
        id: updateData.user.id,
        email: updateData.user.email,
      },
    };

    if (useCookies) {
      const accessCookie = buildCookie(
        "sb-access-token",
        refreshedData.session.access_token,
        COOKIE_OPTIONS
      );
      const refreshCookie = buildCookie(
        "sb-refresh-token",
        refreshedData.session.refresh_token,
        REFRESH_COOKIE_OPTIONS
      );

      responseHeaders.append("Set-Cookie", accessCookie);
      responseHeaders.append("Set-Cookie", refreshCookie);

      console.log(`[AUTH-RESET] [${env}] Cookies set on response`);
    }

    if (includeTokens) {
      responseBody.access_token = refreshedData.session.access_token;
      responseBody.refresh_token = refreshedData.session.refresh_token;
      responseBody.expires_at = refreshedData.session.expires_at;

      console.log(`[AUTH-RESET] [${env}] Tokens included in response body`);
    }

    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers: responseHeaders,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[AUTH-RESET] Unexpected error:", message);

    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      message,
      500,
      corsHeaders
    );
  }
});
