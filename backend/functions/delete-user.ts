import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";

console.info("delete-user function initialized");

const corsHeaders = {
  "Access-Control-Allow-Origin": "*", // ajustar para domínio em produção
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json",
};

function jsonResponse(
  body: unknown,
  status = 200,
  extraHeaders: Record<string, string> = {}
) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { ...corsHeaders, ...extraHeaders },
  });
}

Deno.serve(async (req: Request) => {
  // Handle preflight
  if (req.method === "OPTIONS") {
    return new Response(null, { status: 204, headers: corsHeaders });
  }

  if (req.method !== "POST") {
    return jsonResponse({ error: "Method not allowed" }, 405);
  }

  try {
    const authHeader = req.headers.get("Authorization") ?? "";
    if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) {
      return jsonResponse({ error: "No or invalid Authorization header" }, 401);
    }
    const token = authHeader.split(" ")[1];

    const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
    const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
    const SUPABASE_SERVICE_ROLE_KEY =
      Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";

    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
      return jsonResponse(
        { error: "Missing Supabase environment variables" },
        500
      );
    }

    // Cliente em nome do caller (usa o token passado no Authorization)
    const supabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: `Bearer ${token}` } },
      auth: { persistSession: false, autoRefreshToken: false },
    });

    // Pega usuário que está chamando
    const { data: getUserData, error: getUserError } =
      await supabaseClient.auth.getUser();
    const caller = getUserData?.user ?? null;
    if (getUserError || !caller) {
      return jsonResponse({ error: "Invalid or expired token" }, 401);
    }

    // Verifica se caller é admin
    const { data: profile, error: profileError } = await supabaseClient
      .from("users")
      .select("role")
      .eq("id", caller.id)
      .single();

    if (profileError) {
      console.info(
        "profile read error (caller)",
        profileError.message ?? profileError
      );
      return jsonResponse({ error: "Unable to verify caller role" }, 403);
    }

    if (profile?.role !== "admin") {
      return jsonResponse(
        { error: "Apenas admins podem deletar usuários" },
        403
      );
    }

    // Parse body
    let body: any;
    try {
      body = await req.json();
    } catch (e) {
      return jsonResponse({ error: "Invalid JSON body" }, 400);
    }

    const { user_id } = body ?? {};
    if (!user_id) {
      return jsonResponse({ error: "user_id é obrigatório" }, 400);
    }

    // Validar formato UUID (básico)
    const uuidRegex =
      /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    if (!uuidRegex.test(user_id)) {
      return jsonResponse({ error: "user_id inválido (deve ser UUID)" }, 400);
    }

    // Prevenir que admin delete a si mesmo
    if (user_id === caller.id) {
      return jsonResponse(
        { error: "Você não pode deletar sua própria conta" },
        400
      );
    }

    // Cliente admin (service role) — bypassa RLS
    const supabaseAdmin = createClient(
      SUPABASE_URL,
      SUPABASE_SERVICE_ROLE_KEY,
      {
        auth: { autoRefreshToken: false, persistSession: false },
      }
    );

    // Deleta usuário do Auth (cascateará para public.users via ON DELETE CASCADE)
    const { data: deleteData, error: deleteError } =
      await supabaseAdmin.auth.admin.deleteUser(user_id);

    if (deleteError) {
      const message = (deleteError as any)?.message ?? String(deleteError);
      // Pode ser que o usuário não exista
      if (message.includes("not found") || message.includes("User not found")) {
        return jsonResponse({ error: "Usuário não encontrado" }, 404);
      }
      return jsonResponse(
        { error: "Falha ao deletar usuário", details: message },
        400
      );
    }

    // Sucesso
    return jsonResponse(
      {
        success: true,
        message: "Usuário deletado com sucesso",
        user_id,
      },
      200
    );
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("Unhandled error in delete-user function:", message);
    return jsonResponse(
      { error: "Internal server error", details: message },
      500
    );
  }
});
