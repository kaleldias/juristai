import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
console.info("create-user function initialized");
const corsHeaders = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
  "Access-Control-Allow-Headers": "Content-Type, Authorization",
  "Content-Type": "application/json"
};
function jsonResponse(body, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(body), {
    status,
    headers: {
      ...corsHeaders,
      ...extraHeaders
    }
  });
}
Deno.serve(async (req)=>{
  // Handle preflight
  if (req.method === "OPTIONS") {
    return new Response(null, {
      status: 204,
      headers: corsHeaders
    });
  }
  if (req.method !== "POST") {
    return jsonResponse({
      error: "Method not allowed"
    }, 405);
  }
  try {
    const authHeader = req.headers.get("Authorization") ?? "";
    if (!authHeader || !authHeader.toLowerCase().startsWith("bearer ")) {
      return jsonResponse({
        error: "No or invalid Authorization header"
      }, 401);
    }
    const token = authHeader.split(" ")[1];
    const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
    const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
    const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    if (!SUPABASE_URL || !SUPABASE_ANON_KEY || !SUPABASE_SERVICE_ROLE_KEY) {
      return jsonResponse({
        error: "Missing Supabase environment variables"
      }, 500);
    }
    // Cliente em nome do caller (usa o token passado no Authorization)
    const supabaseClient = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: {
        headers: {
          Authorization: `Bearer ${token}`
        }
      },
      auth: {
        persistSession: false,
        autoRefreshToken: false
      }
    });
    // Pega usuário que está chamando
    const { data: getUserData, error: getUserError } = await supabaseClient.auth.getUser();
    const caller = getUserData?.user ?? null;
    if (getUserError || !caller) {
      return jsonResponse({
        error: "Invalid or expired token"
      }, 401);
    }
    // Verifica se caller é admin na tabela de users (tabela public.users, coluna role)
    const { data: profile, error: profileError } = await supabaseClient.from("users").select("role").eq("id", caller.id).single();
    if (profileError) {
      // Pode ser RLS ou inexistência da tabela; retorne 403 para segurança
      console.info("profile read error (caller)", profileError.message ?? profileError);
      return jsonResponse({
        error: "Unable to verify caller role"
      }, 403);
    }
    if (profile?.role !== "admin") {
      return jsonResponse({
        error: "Apenas admins podem criar usuários"
      }, 403);
    }
    // Parse body
    let body;
    try {
      body = await req.json();
    } catch (e) {
      return jsonResponse({
        error: "Invalid JSON body"
      }, 400);
    }
    const { email, password, full_name, role } = body ?? {};
    if (!email || !password || !full_name) {
      return jsonResponse({
        error: "Email, password e full_name são obrigatórios"
      }, 400);
    }
    // Whitelist de roles permitidas
    const allowedRoles = [
      "user",
      "admin"
    ];
    const newRole = role ?? "user";
    if (!allowedRoles.includes(newRole)) {
      return jsonResponse({
        error: "Role inválida"
      }, 400);
    }
    // Cliente admin (service role) — tem permissão para criar usuários
    const supabaseAdmin = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY, {
      auth: {
        autoRefreshToken: false,
        persistSession: false
      }
    });
    // Cria usuário no Auth
    const { data: createData, error: createError } = await supabaseAdmin.auth.admin.createUser({
      email,
      password,
      email_confirm: true,
      user_metadata: {
        full_name
      }
    });
    if (createError) {
      const message = createError?.message ?? String(createError);
      return jsonResponse({
        error: "Falha ao criar usuário",
        details: message
      }, 400);
    }
    const createdUser = createData?.user ?? null;
    if (!createdUser || !createdUser.id) {
      return jsonResponse({
        error: "Usuário criado, mas resposta incompleta do Auth"
      }, 500);
    }
    // Atualiza a tabela users com a role se necessário
    try {
      const { error: updateError } = await supabaseAdmin.from("users").upsert({
        id: createdUser.id,
        email: createdUser.email,
        full_name,
        role: newRole
      }, {
        onConflict: "id"
      });
      if (updateError) {
        console.info("profile update error (admin)", updateError.message ?? updateError);
        // Não falhar completamente; reportar parcialmente
        return jsonResponse({
          error: "Usuário criado no Auth, mas falha ao inserir/atualizar perfil",
          user: {
            id: createdUser.id,
            email: createdUser.email
          },
          details: updateError.message ?? updateError
        }, 207);
      }
    } catch (e) {
      console.info("exception updating profile", e);
      return jsonResponse({
        error: "Usuário criado no Auth, mas ocorreu um erro ao atualizar perfil",
        user: {
          id: createdUser.id,
          email: createdUser.email
        }
      }, 207);
    }
    // Sucesso
    return jsonResponse({
      success: true,
      user: {
        id: createdUser.id,
        email: createdUser.email,
        role: newRole
      }
    }, 200);
  } catch (err) {
    const message = err instanceof Error ? err.message : String(err);
    console.error("Unhandled error in create-user function:", message);
    return jsonResponse({
      error: "Internal server error",
      details: message
    }, 500);
  }
});
