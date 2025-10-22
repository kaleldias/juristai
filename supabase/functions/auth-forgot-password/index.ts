import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import {
  getCorsHeaders,
  handlePreflight,
  detectEnvironment,
} from "../_shared/cors.ts";
import { jsonResponse, errorResponse } from "../_shared/response.ts";
import type { Environment } from "../_shared/types.ts";

console.log("auth-forgot-password function initialized");

const RESET_PASSWORD_URLS: Record<Environment, string> = {
  PROD: "https://juristai.hashing3.com/reset-password",
  DEV: "https://7eb14f49-5c74-4713-9973-342719cde6fc.weweb-preview.io/reset-password",
};

function resolveRedirectUrl(env: Environment): string {
  return RESET_PASSWORD_URLS[env] ?? RESET_PASSWORD_URLS.DEV;
}

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  console.log(`[AUTH-FORGOT] Origin: ${origin}`);

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
  console.log(`[AUTH-FORGOT] Environment: ${env}`);

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

    const { email } = (body ?? {}) as { email?: unknown };

    if (!email || typeof email !== "string") {
      return errorResponse(
        "Missing email",
        "MISSING_EMAIL",
        "Email is required",
        400,
        corsHeaders
      );
    }

    const cleanedEmail = email.trim().toLowerCase();

    if (!cleanedEmail) {
      return errorResponse(
        "Missing email",
        "MISSING_EMAIL",
        "Email is required",
        400,
        corsHeaders
      );
    }

    const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);
    const redirectTo = resolveRedirectUrl(env);

    console.log(`[AUTH-FORGOT] Sending reset email to: ${cleanedEmail}`);
    console.log(`[AUTH-FORGOT] Redirect URL: ${redirectTo}`);

    const { error } = await supabase.auth.resetPasswordForEmail(cleanedEmail, {
      redirectTo,
    });

    if (error) {
      console.error("[AUTH-FORGOT] Supabase reset error:", error.message);
      return errorResponse(
        "Failed to send reset email",
        "RESET_FAILED",
        error.message || "Unable to send password reset email",
        400,
        corsHeaders
      );
    }

    return jsonResponse(
      {
        success: true,
        message: "Password reset link sent. Check your email.",
      },
      200,
      corsHeaders
    );
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[AUTH-FORGOT] Unexpected error:", message);

    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      message,
      500,
      corsHeaders
    );
  }
});
