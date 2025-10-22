// ============================================
// CLOUDFLARE WORKER - SUPABASE PROXY
// Suporta: DEV (Authorization header) + PROD (Cookies)
// ============================================

const SUPABASE_URL = "https://xktrrferorupahtmxkdi.supabase.co";

const ALLOWED_ORIGINS = [
  "https://juristai.hashing3.com",
  "https://7eb14f49-5c74-4713-9973-342719cde6fc.weweb-preview.io",
  "https://editor.weweb.io",
  "https://cdn.weweb.io",
];

const PRODUCTION_ORIGINS = ["https://juristai.hashing3.com"];

// ============================================
// HANDLER PRINCIPAL
// ============================================
addEventListener("fetch", (event) => {
  event.respondWith(handleRequest(event.request));
});

async function handleRequest(request) {
  const url = new URL(request.url);
  const origin = request.headers.get("Origin");

  console.log(`[PROXY] ===== NEW REQUEST =====`);
  console.log(`[PROXY] ${request.method} ${url.pathname}`);
  console.log(`[PROXY] Origin: ${origin}`);

  // ============================================
  // 1. VERIFICAR SE É ROTA /api/*
  // ============================================
  if (!url.pathname.startsWith("/api/")) {
    console.log(`[PROXY] Not an API route`);
    return new Response("Not found", { status: 404 });
  }

  // ============================================
  // 2. MAPEAR /api/* → /functions/v1/*
  // ============================================
  const newPath = url.pathname.replace("/api/", "/functions/v1/");
  const supabaseUrl = `${SUPABASE_URL}${newPath}${url.search}`;

  console.log(`[PROXY] Forwarding to: ${supabaseUrl}`);

  // ============================================
  // 3. CORS PREFLIGHT (OPTIONS)
  // ============================================
  if (request.method === "OPTIONS") {
    console.log(`[PROXY] Handling OPTIONS preflight`);
    return handlePreFlight(origin);
  }

  // ============================================
  // 4. DETECTAR MODO: DEV ou PROD
  // ============================================
  const mode = detectEnvironment(origin);
  const isProd = mode === "PROD";

  console.log(`[PROXY] Environment: ${mode}`);
  console.log(`[PROXY] Will process cookies: ${isProd}`);

  // ============================================
  // 5. PREPARAR REQUISIÇÃO PARA SUPABASE
  // ============================================
  const headers = new Headers();

  // Headers sempre necessários
  const headersToForward = [
    "Content-Type",
    "apikey",
    "Authorization",
    "Origin",
    "X-Client-Info",
    "X-Supabase-Auth",
    "X-Requested-With",
    "X-Refresh-Token", // ← Adiciona support para DEV mode
  ];

  headersToForward.forEach((headerName) => {
    const value = request.headers.get(headerName);
    if (value) {
      headers.set(headerName, value);
      console.log(`[PROXY] Forwarding: ${headerName}`);
    }
  });

  // ============================================
  // MODO PROD: Passar cookies se houver
  // ============================================
  if (isProd) {
    const cookies = request.headers.get("Cookie");
    if (cookies) {
      headers.set("Cookie", cookies);
      console.log("[PROXY] [PROD] Forwarding cookies to Supabase");
    } else {
      console.log("[PROXY] [PROD] No cookies to forward (first login)");
    }
  } else {
    console.log("[PROXY] [DEV] NOT forwarding cookies (dev mode)");
  }

  // Criar nova requisição
  const supabaseRequest = new Request(supabaseUrl, {
    method: request.method,
    headers,
    body: request.body,
    redirect: "follow",
  });

  // ============================================
  // 6. FAZER REQUISIÇÃO AO SUPABASE
  // ============================================
  let response;
  try {
    response = await fetch(supabaseRequest);
    console.log(`[PROXY] Supabase response: ${response.status}`);
  } catch (error) {
    console.error("[PROXY] Connection error:", error);
    return jsonResponse(
      { error: "Erro ao conectar com Supabase" },
      502,
      getCorsHeaders(origin)
    );
  }

  // ============================================
  // 7. CLONAR RESPONSE PARA LER HEADERS
  // ============================================
  // IMPORTANTE: Necessário clonar porque tem que iterar pelos headers
  const clonedResponse = response.clone();

  // ============================================
  // 8. CONSTRUIR HEADERS DA RESPOSTA
  // ============================================
  const responseHeaders = new Headers();

  // Adicionar CORS headers PRIMEIRO
  const corsHeaders = getCorsHeaders(origin);
  Object.entries(corsHeaders).forEach(([key, value]) => {
    responseHeaders.set(key, value);
  });

  // ============================================
  // 9. COPIAR HEADERS DA RESPOSTA (INCLUINDO SET-COOKIE!)
  // ============================================
  // Iterar com forEach para capturar TODOS os Set-Cookie
  const setCookies = [];

  clonedResponse.headers.forEach((value, key) => {
    const lowerKey = key.toLowerCase();

    if (lowerKey === "set-cookie") {
      // Armazenar Set-Cookie separadamente
      setCookies.push(value);
      console.log(`[PROXY] Found Set-Cookie: ${value.substring(0, 50)}...`);
    } else if (
      lowerKey !== "access-control-allow-origin" &&
      lowerKey !== "access-control-allow-credentials" &&
      lowerKey !== "access-control-allow-methods" &&
      lowerKey !== "access-control-allow-headers"
    ) {
      // Copiar outros headers (exceto CORS que já setamos)
      responseHeaders.set(key, value);
    }
  });

  console.log(`[PROXY] Found ${setCookies.length} Set-Cookie header(s)`);

  // ============================================
  // 10. PROCESSAR COOKIES (SÓ EM PROD)
  // ============================================
  if (isProd && setCookies.length > 0) {
    console.log("[PROXY] [PROD] Processing cookies...");

    setCookies.forEach((cookie, index) => {
      const fixedCookie = fixCookie(cookie);
      responseHeaders.append("Set-Cookie", fixedCookie);
      console.log(
        `[PROXY] [PROD] Cookie ${index + 1}: ${fixedCookie.substring(0, 60)}...`
      );
    });
  } else if (isProd) {
    console.log("[PROXY] [PROD] No cookies to process");
  } else {
    console.log("[PROXY] [DEV] Skipping cookie processing (dev mode)");
  }

  // ============================================
  // 11. RETORNAR RESPOSTA
  // ============================================
  console.log(`[PROXY] ===== END REQUEST =====\n`);

  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers: responseHeaders,
  });
}

// ============================================
// FUNÇÕES AUXILIARES - AMBIENTE
// ============================================

function normalizeOrigin(origin) {
  if (!origin) return "";
  return origin.replace(/\/$/, "");
}

function detectEnvironment(origin) {
  if (!origin) {
    return "PROD";
  }

  const normalized = normalizeOrigin(origin);

  if (PRODUCTION_ORIGINS.some((prod) => normalizeOrigin(prod) === normalized)) {
    return "PROD";
  }

  if (
    origin.includes("weweb-preview.io") ||
    origin.includes("editor.weweb.io") ||
    origin.includes("cdn.weweb.io") ||
    origin.includes("localhost") ||
    origin.includes("127.0.0.1")
  ) {
    return "DEV";
  }

  return "PROD";
}

// ============================================
// FUNÇÕES AUXILIARES - HTTP
// ============================================

function jsonResponse(body, status = 200, headers = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      "Content-Type": "application/json",
      ...headers,
    },
  });
}

function getCorsHeaders(origin) {
  const normalized = normalizeOrigin(origin);
  const allowedOrigin =
    origin &&
    ALLOWED_ORIGINS.some((allowed) => normalizeOrigin(allowed) === normalized)
      ? origin
      : ALLOWED_ORIGINS[0];

  return {
    "Access-Control-Allow-Origin": allowedOrigin,
    "Access-Control-Allow-Credentials": "true",
    "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
    "Access-Control-Allow-Headers":
      "Content-Type, Authorization, X-Client-Info, apikey, X-Supabase-Auth, X-Requested-With, X-Refresh-Token",
    "Access-Control-Expose-Headers": "Set-Cookie, Authorization",
  };
}

function handlePreFlight(origin) {
  return new Response(null, {
    status: 204,
    headers: getCorsHeaders(origin),
  });
}

// ============================================
// FUNÇÕES AUXILIARES - COOKIES
// ============================================

function fixCookie(cookie) {
  let fixed = cookie;

  // Remove Domain (deixa browser definir automaticamente)
  fixed = fixed.replace(/Domain=[^;]+;?\s*/gi, "");

  // Remove SameSite existente
  fixed = fixed.replace(/;\s*SameSite=[^;]*/gi, "");

  // Garantir Path
  if (!fixed.includes("Path=")) {
    fixed += "; Path=/";
  }

  // Garantir HttpOnly
  if (!fixed.includes("HttpOnly")) {
    fixed += "; HttpOnly";
  }

  // Garantir Secure
  if (!fixed.includes("Secure")) {
    fixed += "; Secure";
  }

  // Adicionar SameSite=None para suportar cookies cross-site
  fixed += "; SameSite=None";

  return fixed;
}
