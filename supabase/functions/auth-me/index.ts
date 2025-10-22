import "jsr:@supabase/functions-js/edge-runtime.d.ts";
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
  getUserProfile,
} from "../_shared/auth.ts";

console.log("auth-me function initialized");

Deno.serve(async (req) => {
  // ===== SETUP CORS =====
  const origin = req.headers.get("Origin");
  const corsHeaders = getCorsHeaders(origin);

  console.log(`[AUTH-ME] Origin: ${origin}`);

  // =====  HANDLE PREFLIGHT =====
  if (req.method === "OPTIONS") {
    return handlePreflight(origin);
  }

  // ===== VALIDAR MÉTODO =====
  if (req.method !== "GET") {
    return errorResponse(
      "Method not allowed",
      "METHOD_NOT_ALLOWED",
      "Only GET requests are allowed",
      405,
      corsHeaders
    );
  }

  // =====  DETECTAR AMBIENTE =====
  const env = detectEnvironment(origin);
  const useCookies = shouldUseCookies(origin);
  const includeTokens = shouldIncludeTokensInBody(origin);

  console.log(`[AUTH-ME] Environment: ${env}`);
  console.log(`[AUTH-ME] Use cookies: ${useCookies}`);
  console.log(`[AUTH-ME] Include tokens in body: ${includeTokens}`);

  try {
    // =====  EXTRAIR TOKENS =====
    const tokens = extractTokens(req);

    if (!tokens) {
      console.log("[AUTH-ME] No tokens found");
      return errorResponse(
        "Not authenticated",
        "NO_TOKEN",
        "Please login again",
        401,
        corsHeaders
      );
    }

    console.log(
      `[AUTH-ME] Tokens extracted - has refresh: ${!!tokens.refreshToken}`
    );

    // =====  VALIDAR ACCESS TOKEN =====
    console.log("[AUTH-ME] Validating access token...");
    let authResult = await validateAccessToken(tokens.accessToken);

    console.log(`[AUTH-ME] DEBUG: authenticated = ${authResult.authenticated}`);
    console.log(`[AUTH-ME] DEBUG: has refreshToken = ${!!tokens.refreshToken}`);

    // ===== SE TOKEN INVÁLIDO, TENTAR REFRESH =====
    if (!authResult.authenticated && tokens.refreshToken) {
      console.log("[AUTH-ME] >>> ENTERING REFRESH BLOCK <<<");
      authResult = await refreshSession(tokens.refreshToken);

      // =====  SE REFRESH TAMBÉM FALHOU =====
      if (!authResult.authenticated) {
        console.log("[AUTH-ME] Refresh failed - both tokens invalid");
        return errorResponse(
          authResult.error || "Session expired",
          authResult.code || "TOKEN_EXPIRED",
          "Please login again",
          401,
          corsHeaders
        );
      }

      // =====  SE REFRESH FUNCIONOU =====
      console.log("[AUTH-ME] Session refreshed successfully");

      // Buscar perfil do usuário
      const profile = await getUserProfile(
        authResult.user.id,
        authResult.user.email,
        authResult.accessToken!
      );

      if (!profile) {
        console.log("[AUTH-ME] Profile not found");
        return errorResponse(
          "Profile not found",
          "PROFILE_ERROR",
          "User profile not found",
          404,
          corsHeaders
        );
      }

      // Preparar headers de resposta
      const responseHeaders = new Headers(corsHeaders);
      responseHeaders.set("Content-Type", "application/json");

      console.log(`[AUTH-ME] DEBUG: useCookies = ${useCookies}`);
      console.log(`[AUTH-ME] DEBUG: includeTokens = ${includeTokens}`);

      // =====  ADICIONAR COOKIES SE FOR PROD =====
      if (useCookies) {
        console.log("[AUTH-ME] Building cookies...");

        const newAccessCookie = buildCookie(
          "sb-access-token",
          authResult.accessToken!,
          COOKIE_OPTIONS
        );

        const newRefreshCookie = buildCookie(
          "sb-refresh-token",
          authResult.refreshToken!,
          REFRESH_COOKIE_OPTIONS
        );

        console.log(
          `[AUTH-ME] Access cookie: ${newAccessCookie.substring(0, 50)}...`
        );
        console.log(
          `[AUTH-ME] Refresh cookie: ${newRefreshCookie.substring(0, 50)}...`
        );

        responseHeaders.append("Set-Cookie", newAccessCookie);
        responseHeaders.append("Set-Cookie", newRefreshCookie);
        console.log(`[AUTH-ME] [${env}] Cookies added to headers`);
      } else {
        console.log("[AUTH-ME] Skipping cookies (useCookies = false)");
      }

      // =====  PREPARAR BODY DA RESPOSTA =====
      const responseBody: any = {
        success: true,
        user: { ...profile, email: authResult.user.email },
        refreshed: true,
      };

      // =====  INCLUIR TOKENS NO BODY SE FOR DEV =====
      if (includeTokens) {
        console.log("[AUTH-ME] Adding tokens to body...");
        responseBody.access_token = authResult.accessToken;
        responseBody.refresh_token = authResult.refreshToken;
        console.log(`[AUTH-ME] [${env}] Tokens included in body`);
      } else {
        console.log(
          "[AUTH-ME] Skipping tokens in body (includeTokens = false)"
        );
      }

      console.log(
        `[AUTH-ME] Returning response with ${Object.keys(responseBody).length} keys`
      );
      console.log(
        `[AUTH-ME] Response body keys: ${Object.keys(responseBody).join(", ")}`
      );

      return new Response(JSON.stringify(responseBody), {
        status: 200,
        headers: responseHeaders,
      });
    }

    // =====  SE AINDA NÃO AUTENTICADO (SEM REFRESH TOKEN) =====
    if (!authResult.authenticated) {
      console.log("[AUTH-ME] >>> ENTERING ERROR BLOCK (no refresh token) <<<");
      return errorResponse(
        authResult.error || "Authentication failed",
        authResult.code || "AUTH_ERROR",
        "Please login again",
        401,
        corsHeaders
      );
    }

    // =====  TOKEN VÁLIDO - BUSCAR PERFIL =====
    console.log(
      "[AUTH-ME] >>> ENTERING VALID TOKEN BLOCK (no refresh needed) <<<"
    );
    const profile = await getUserProfile(
      authResult.user.id,
      authResult.user.email,
      authResult.accessToken!
    );

    if (!profile) {
      console.log("[AUTH-ME] Profile not found");
      return errorResponse(
        "Profile not found",
        "PROFILE_ERROR",
        "User profile not found",
        404,
        corsHeaders
      );
    }

    // ===== RETORNAR SUCESSO (TOKEN VÁLIDO, SEM REFRESH) =====
    console.log("[AUTH-ME] Returning user profile (no refresh needed)");
    const responseBody: any = {
      success: true,
      user: authResult.user.email,
      refreshed: false,
    };

    console.log(
      "[AUTH-ME] Response will NOT include tokens (no refresh happened)"
    );

    return jsonResponse(responseBody, 200, corsHeaders);
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error);
    console.error("[AUTH-ME] Unhandled error:", message);

    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      message,
      500,
      corsHeaders
    );
  }
});
