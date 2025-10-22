import type { CookieOptions, SuccessResponse, ErrorResponse } from "./types.ts";

export function jsonResponse(
  body: SuccessResponse | ErrorResponse,
  status = 200,
  headers: HeadersInit = {}
): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json", ...headers },
  });
}

export function errorResponse(
  error: string,
  code: string,
  message: string,
  status: number,
  corsHeaders: HeadersInit
): Response {
  return jsonResponse({ error, code, message }, status, corsHeaders);
}

/* prettier-ignore */
export function buildCookie(name: string, value: string, options: CookieOptions): string {
  const parts = [`${name}=${value}`, `Max-Age=${options.maxAge}`, `Path=${options.path}`];
  if (options.httpOnly) parts.push("HttpOnly");
  if (options.secure) parts.push("Secure");
  if (options.sameSite) parts.push(`SameSite=${options.sameSite}`);

  return parts.join("; ");
}

export const COOKIE_OPTIONS: CookieOptions = {
  httpOnly: true,
  secure: true,
  sameSite: "None",
  path: "/",
  maxAge: 3600,
};

export const REFRESH_COOKIE_OPTIONS: CookieOptions = {
  ...COOKIE_OPTIONS,
  maxAge: 604800, // 7 dias
};
