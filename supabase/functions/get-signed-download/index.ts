import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { getCorsHeaders, handlePreflight } from "../_shared/cors.ts";
import { jsonResponse, errorResponse } from "../_shared/response.ts";
import { extractTokens } from "../_shared/auth.ts";

type ContractFileRaw = {
  id: string;
  user_id: string;
  storage_bucket: string;
  storage_path: string;
  mime_type: string;
  size_bytes: number;
  sha256: string;
};

const ENC = new TextEncoder();

async function hmacSha256Hex(secret: string, payload: unknown) {
  const key = await crypto.subtle.importKey(
    "raw",
    ENC.encode(secret),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign"]
  );
  const data = ENC.encode(JSON.stringify(payload));
  const sig = await crypto.subtle.sign("HMAC", key, data);
  // prettier-ignore
  return [...new Uint8Array(sig)].map(b => b.toString(16).padStart(2, "0")).join("");
}

Deno.serve(async (req: Request) => {
  const origin = req.headers.get("Origin");
  const cors = { ...getCorsHeaders(origin), "Cache-Control": "no-store" };

  if (req.method === "OPTIONS") return handlePreflight(origin);

  if (req.method !== "POST") {
    return errorResponse(
      "Method not allowed",
      "METHOD_NOT_ALLOWED",
      "Only POST",
      405,
      cors
    );
  }

  try {
    const body = await req.json().catch(() => ({}));
    const { contract_file_id } = body as { contract_file_id?: string };

    if (!contract_file_id) {
      return errorResponse(
        "Missing field",
        "MISSING_CONTRACT_FILE_ID",
        "contract_file_id is required",
        400,
        cors
      );
    }

    // ENV
    const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
    const SUPABASE_ANON_KEY = Deno.env.get("SUPABASE_ANON_KEY") ?? "";
    // prettier-ignore
    const SUPABASE_SERVICE_ROLE_KEY = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
    const N8N_INGEST_WEBHOOK_URL = Deno.env.get("N8N_INGEST_WEBHOOK_URL") ?? "";
    const INGEST_HMAC_SECRET = Deno.env.get("INGEST_HMAC_SECRET") ?? "";
    const SIGNED_URL_TTL_SECONDS =
      Deno.env.get("SIGNED_URL_TTL_SECONDS") ?? "300"; // 5minuts

    if (
      !SUPABASE_URL ||
      !SUPABASE_ANON_KEY ||
      !SUPABASE_SERVICE_ROLE_KEY ||
      !N8N_INGEST_WEBHOOK_URL ||
      !INGEST_HMAC_SECRET
    ) {
      return errorResponse(
        "Configuration error",
        "ENV_ERROR",
        "Missing env vars",
        500,
        cors
      );
    }

    const tokens = extractTokens(req);
    if (!tokens?.accessToken) {
      // prettier-ignore
      return errorResponse("Not authenticated", "NO_TOKEN", "Please login", 401, cors);
    }

    // Buscar arquivo do próprio usuario
    const userSb = createClient(SUPABASE_URL, SUPABASE_ANON_KEY, {
      global: { headers: { Authorization: `Bearer ${tokens.accessToken}` } },
    });

    const { data: file, error: fileErr } = await userSb
      .from("contract_files")
      .select(
        "id, user_id, storage_bucket, storage_path, mime_type, size_bytes, sha256"
      )
      .eq("id", contract_file_id)
      .single<ContractFileRaw>();

    if (fileErr || !file) {
      return errorResponse(
        "Not found",
        "CONTRACT_FILE_NOT_FOUND",
        fileErr?.message || "File not found or not owned by user",
        404,
        cors
      );
    }

    // Criar Signed URL (service role)
    // prettier-ignore
    const serviceRoleClient = createClient(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY);
    const { data: signedUrl, error: signedErr } =
      await serviceRoleClient.storage
        .from(file.storage_bucket)
        .createSignedUrl(file.storage_path, SIGNED_URL_TTL_SECONDS);

    console.log('signedUrl:', signedUrl)
    if (signedErr || !signedUrl) {
      return errorResponse(
        "Signed URL error",
        "SIGNED_URL_FAILED",
        signedErr?.message || "Could not create signed URL",
        500,
        cors
      );
    }

    // Payload n8n
    const payload = {
      contract_file_id: file.id,
      user_id: file.user_id,
      storage_bucket: file.storage_bucket,
      storage_path: file.storage_path,
      signed_url: signedUrl.signedUrl,
      expires_in: SIGNED_URL_TTL_SECONDS,
      sha256: file.sha256,
      mime_type: file.mime_type,
      size_bytes: file.size_bytes ?? null,
      timestamp: new Date().toISOString(),
    };

    const signature = await hmacSha256Hex(INGEST_HMAC_SECRET, payload);

    // POST ao Webhook do n8n
    const n8nRes = await fetch(N8N_INGEST_WEBHOOK_URL, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        "X-Signature": `sha256=${signature}`,
      },
      body: JSON.stringify(payload),
    });

    const n8nOk = n8nRes.ok;
    const n8nText = await n8nRes.text().catch(() => "");

    if (!n8nOk) {
      // Devolver o SignedURL mesmo assim, mas sinalizar falha no enqueue
      return jsonResponse(
        {
          success: false,
          enqueued: false,
          reason: "N8N_WEBHOOK_FAILED",
          n8n_status: n8nRes.status,
          n8n_body: n8nText,
          signed_url: signedUrl.signedUrl,
          expires_in: SIGNED_URL_TTL_SECONDS,
          contract_file_id: file.id,
        },
        502,
        cors
      );
    }

    // Resposta ao caller
    return jsonResponse({
      success: true,
      enqueued: true,
      signed_url: signedUrl.signedUrl,
      expires_in: SIGNED_URL_TTL_SECONDS,
      contract_file_id: file.id,
    }, 202, cors);


  } catch (error) {
    const msg = error instanceof Error ? error.message : String(error);
    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      msg,
      500,
      cors
    );
  }
});