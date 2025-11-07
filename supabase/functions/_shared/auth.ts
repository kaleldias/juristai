import { createClient } from "jsr:@supabase/supabase-js@2";
import type { AuthResult, TokenPair, UserProfile } from "./types.ts";

const SUPABASE_URL = Deno.env.get("SUPABASE_URL")!;
const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY")!;

/**
 * Extrai tokens de autenticação da requisição
 * PRIORIDADE 1: Cookies (sb-access-token, sb-refresh-token)
 * PRIORIDADE 2: Headers (Authorization: Bearer, X-Refresh-Token)
 */
export function extractTokens(req: Request): TokenPair | null {
  let accessToken: string | null = null;
  let refreshToken: string | null = null;

  // ===== PRIORIDADE 1: COOKIES (PROD) =====
  const cookieHeader = req.headers.get("Cookie");
  console.log(`[AUTH] Cookie header presente: ${!!cookieHeader}`);

  if (cookieHeader) {
    console.log(`[AUTH] Cookie header: ${cookieHeader.substring(0, 100)}...`);
    const cookies: Record<string, string> = {};

    cookieHeader.split("; ").forEach((cookie) => {
      const [name, ...rest] = cookie.split("=");
      if (name) {
        cookies[name] = rest.join("=");
      }
    });

    accessToken = cookies["sb-access-token"];
    refreshToken = cookies["sb-refresh-token"];

    if (accessToken || refreshToken) {
      console.log(
        `[AUTH] Tokens extraídos de cookies - access: ${!!accessToken}, refresh: ${!!refreshToken}`
      );
      return { accessToken, refreshToken };
    }
  }

  // ===== PRIORIDADE 2: HEADERS (DEV) =====
  const authHeader = req.headers.get("Authorization");
  const refreshHeader = req.headers.get("X-Refresh-Token");

  if (authHeader?.startsWith("Bearer ")) {
    accessToken = authHeader.substring(7);
    refreshToken = refreshHeader; // Pode ser null

    console.log("[AUTH] Access token extraído do header Authorization (desenvolvimento)");

    if (refreshToken) {
      // prettier-ignore
      console.log("[AUTH] Refresh token extraído do header X-Refresh-Token (desenvolvimento)");
    } else {
      // prettier-ignore
      console.log("[AUTH] Refresh token não fornecido - refresh automático não será possível");
    }

    return { accessToken, refreshToken };
  }

  // ===== NENHUM TOKEN ENCONTRADO =====
  console.log("[AUTH] Nenhum token encontrado (nem cookies, nem headers)");
  return null;
}

// Valida o access token com o Supabase Auth
// prettier-ignore
export async function validateAccessToken(accessToken: string): Promise<AuthResult> {
  const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

  const {data: { user }, error,} = await supabase.auth.getUser(accessToken);

  if (error || !user) {
    return {
      authenticated: false,
      user: null,
      error: "Invalid token",
      code: "INVALID_TOKEN",
    };
  }

  return {
    authenticated: true,
    user,
    accessToken,
  };
}

// Tenta renovar sessão usando refresh token 
// prettier-ignore
export async function refreshSession(refreshToken: string): Promise<AuthResult> {
  const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY);

  const { data: refreshData, error } = await supabase.auth.refreshSession({
    refresh_token: refreshToken,
  });

  if (error || !refreshData.session) {
    return {
      authenticated: false,
      user: null,
      error: "Session expired",
      code: "TOKEN_EXPIRED",
    };
  }

  return {
    authenticated: true,
    user: refreshData.user,
    accessToken: refreshData.session.access_token,
    refreshToken: refreshData.session.refresh_token,
  };
}

// Busca perfil do usuário no banco (tabela public.users)
export async function getUserProfile(
  userId: string,
  email: string,
  accessToken: string
): Promise<UserProfile | null> {
  const supabase = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
    global: {
      headers: {
        Authorization: `Bearer ${accessToken}`,
      },
    },
  });

  const { data: profile, error } = await supabase
    .from("users")
    .select("role, plan, full_name")
    .eq("id", userId)
    .single();

  if (error || !profile) {
    console.error("[AUTH] Erro ao buscar perfil:", error?.message);
    return null;
  }

  return {
    id: userId,
    email,
    role: profile.role,
    plan: profile.plan,
    full_name: profile.full_name,
  };
}
