import { Environment } from "../_shared/types.ts";

const ALLOWED_ORIGINS = [
  "https://juristai.hashing3.com",
  "https://7eb14f49-5c74-4713-9973-342719cde6fc.weweb-preview.io",
  "https://editor.weweb.io",
  "https://cdn.weweb.io",
];

const DEV_ORIGINS = [
  "https://editor.weweb.io",
  "https://7eb14f49-5c74-4713-9973-342719cde6fc.weweb-preview.io",
];

const PRODUCTION_ORIGINS = ["https://juristai.hashing3.com"];

function normalizeOrigin(origin: string | null): string {
  if (!origin) return "";
  return origin.replace(/\/$/, "");
}

// Verifica se origin é permitida
export function isOriginAllowed(origin: string | null): boolean {
  if (!origin) return false;

  const normalized = normalizeOrigin(origin);

  return (
    // prettier-ignore
    ALLOWED_ORIGINS.some((allowed) => normalizeOrigin(allowed) === normalized) ||
    origin.includes("weweb-preview.io") ||
    origin.includes("editor.weweb.io") ||
    origin.includes("localhost") ||
    origin.includes("127.0.0.1")
  );
}

// Detecta ambiente baseado na origin
export function detectEnvironment(origin: string | null): Environment {
  if (!origin) {
    return "PROD"; // Default seguro
  }

  const normalized = normalizeOrigin(origin);

  // Produção: origens de produção explícitas
  if (PRODUCTION_ORIGINS.some((prod) => normalizeOrigin(prod) === normalized)) {
    return "PROD";
  }

  // Desenvolvimento: tudo resto (WeWeb editor, preview, localhost)
  return "DEV";
}

// Verifica se deve usar cookies (apenas em PROD)
export function shouldUseCookies(origin: string | null): boolean {
  return detectEnvironment(origin) === "PROD";
}

// Verifica se deve incluir tokens no body (apenas em DEV)
export function shouldIncludeTokensInBody(origin: string | null): boolean {
  return detectEnvironment(origin) === "DEV";
}

// Retorna headers CORS apropriados
export function getCorsHeaders(origin: string | null): HeadersInit {
  /* prettier-ignore */
  const allowedOrigin = ALLOWED_ORIGINS.includes(origin ?? "") ? origin : ALLOWED_ORIGINS[0];

  return {
    "Access-Control-Allow-Origin": allowedOrigin!,
    Vary: "Origin",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":
      "Authorization, apikey, x-client-info, x-supabase-auth, x-requested-with, content-type",
    "Access-Control-Expose-Headers": "Authorization, apikey",
    "Access-Control-Allow-Credentials": "true",
    "Content-Type": "application/json",
  };
}

// Resposta para preflight (OPTIONS)
export function handlePreflight(origin: string | null): Response {
  return new Response(null, { status: 204, headers: getCorsHeaders(origin) });
}
