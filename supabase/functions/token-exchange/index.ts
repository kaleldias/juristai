import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import {
  getCorsHeaders,
  handlePreflight,
  detectEnvironment,
} from "../_shared/cors.ts";
import {
  jsonResponse,
  errorResponse,
} from "../_shared/response.ts";
import {
  extractTokens,
  validateAccessToken,
} from "../_shared/auth.ts";

console.log("token-exchange function initialized");

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  // CORS preflight
  if (req.method === "OPTIONS") {
    return handlePreflight(origin);
  }

  // Aceita GET e POST (POST permite mandar refresh_token no body em DEV)
  if (req.method !== "GET") {
    return errorResponse(
      "Method not allowed",
      "METHOD_NOT_ALLOWED",
      "Only GET are allowed",
      405,
      corsHeaders
    );
  }

  const env = detectEnvironment(origin);

  try {
    // Extrair tokens
    let tokens = extractTokens(req);


    if (!tokens) {
      return errorResponse(
        "Not authenticated",
        "NO_TOKEN",
        "Missing credentials (cookies/headers)",
        401,
        corsHeaders
      );
    }

    // Validar access token
    let authResult = tokens.accessToken
      ? await validateAccessToken(tokens.accessToken)
      : {
          authenticated: false,
          user: null,
          accessToken: undefined as string | undefined,
        };


    if (!authResult.authenticated || !authResult.user || !authResult.accessToken) {
      return errorResponse(
        "Session expired",
        "TOKEN_EXPIRED",
        "Please login again",
        401,
        corsHeaders
      );
    }

    // Response body
    const responseBody: Record<string, unknown> = {
      success: true,
      authenticated: true,
      user: {
        id: authResult.user.id,
        access_token: authResult.accessToken,
      },
    };

    const headers = new Headers(corsHeaders);

    return new Response(JSON.stringify(responseBody), {
      status: 200,
      headers,
    });
  } catch (error) {
    const message = error instanceof Error ? error.message : "Unknown error";
    return errorResponse(
      "Internal error",
      "UNEXPECTED",
      message,
      500,
      corsHeaders
    );
  }
});
