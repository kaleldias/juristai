// supabase/functions/upload-contract/index.ts
import "jsr:@supabase/functions-js/edge-runtime.d.ts";
import { createClient } from "jsr:@supabase/supabase-js@2";
import { getCorsHeaders, handlePreflight } from "../_shared/cors.ts";
import { jsonResponse, errorResponse } from "../_shared/response.ts";
import { extractTokens, validateAccessToken } from "../_shared/auth.ts";

const BUCKET = "contracts";
const MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024; // 10 MB

// ---------- helpers ----------
const toHex = (buf: ArrayBuffer) => {
  const arr = [...new Uint8Array(buf)];
  console.log('Resultado visão bytes:', arr)
  const hex = arr.map((b) => b.toString(16).padStart(2, "0")).join("");
  console.log('Resultado hexadecimal:', hex)
};

const sha256Hex = async (buf: ArrayBuffer) =>
  toHex(await crypto.subtle.digest("SHA-256", buf));

const isPdfMagic = (bytes: Uint8Array) =>
  new TextDecoder().decode(bytes.slice(0, 5)) === "%PDF-";

const buildStoragePath = (userId: string) => {
  const id = crypto.randomUUID();
  const now = new Date();
  const yyyy = now.getUTCFullYear();
  const mm = String(now.getUTCMonth() + 1).padStart(2, "0");
  return `${userId}/${yyyy}/${mm}/${id}.pdf`;
};

// ---------- handler ----------
Deno.serve(async (req) => {
  const origin = req.headers.get("Origin") ?? "";
  const cors = getCorsHeaders(origin);

  // CORS preflight
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

  // envs mínimos
  const SUPABASE_URL = Deno.env.get("SUPABASE_URL") ?? "";
  const SERVICE_ROLE = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY") ?? "";
  if (!SUPABASE_URL || !SERVICE_ROLE) {
    return errorResponse(
      "Configuration error",
      "ENV_ERROR",
      "Missing SUPABASE_URL/SERVICE_ROLE",
      500,
      cors
    );
  }

  try {
    // 1) auth (somente validar; sem refresh aqui)
    const tokens = extractTokens(req);
    if (!tokens?.accessToken) {
      return errorResponse(
        "Not authenticated",
        "NO_TOKEN",
        "Login required",
        401,
        cors
      );
    }
    const auth = await validateAccessToken(tokens.accessToken);
    if (!auth.authenticated || !auth.user?.id) {
      return errorResponse(
        "Invalid or expired token",
        "INVALID_TOKEN",
        "Login required",
        401,
        cors
      );
    }
    const userId = auth.user.id;

    // 2) form-data + validações
    const form = await req.formData();
    console.log(form)
    const file = form.get("file");
    if (!(file instanceof File)) {
      return errorResponse(
        "Missing file",
        "MISSING_FILE",
        "Field 'file' is required",
        400,
        cors
      );
    }
    if (!file.name.toLowerCase().endsWith(".pdf")) {
      return errorResponse(
        "Invalid file format",
        "INVALID_FORMAT",
        "Only .pdf allowed",
        400,
        cors
      );
    }
    if (file.size <= 0) {
      return errorResponse(
        "Empty file",
        "EMPTY_FILE",
        "File is empty",
        400,
        cors
      );
    }
    if (file.size > MAX_FILE_SIZE_BYTES) {
      return errorResponse(
        "File too large",
        "FILE_TOO_LARGE",
        `Max ${Math.floor(MAX_FILE_SIZE_BYTES / (1024 * 1024))}MB`,
        413,
        cors
      );
    }

    const titleInput = form.get("title");
    const title =
      (typeof titleInput === "string" && titleInput.trim()) ||
      file.name.replace(/\.pdf$/i, "") ||
      "Contrato";

    let meta: Record<string, unknown> = {};
    const metaInput = form.get("meta");
    if (typeof metaInput === "string" && metaInput.trim()) {
      try {
        meta = JSON.parse(metaInput);
      } catch {
        meta = {};
      }
    }

    // 3) hash + assinatura do arquivo (defesa extra)
    const buf = await file.arrayBuffer();
    const bytes = new Uint8Array(buf);
    if (!isPdfMagic(bytes)) {
      return errorResponse(
        "Invalid PDF",
        "INVALID_PDF_MAGIC",
        "File header mismatch",
        400,
        cors
      );
    }
    const sha256 = await sha256Hex(buf);

    // 4) supabase admin client
    const supabase = createClient(SUPABASE_URL, SERVICE_ROLE, {
      auth: { persistSession: false, autoRefreshToken: false },
    });

    // 5) checagem rápida de duplicidade (curto-circuito)
    const { data: dup, error: dupErr } = await supabase
      .from("contract_files")
      .select("id")
      .eq("user_id", userId)
      .eq("sha256", sha256)
      .maybeSingle();

    if (dupErr) {
      return errorResponse(
        "Database error",
        "DUP_CHECK_FAILED",
        dupErr.message,
        500,
        cors
      );
    }
    if (dup) {
      return errorResponse(
        "Duplicate file",
        "DUPLICATE_FILE",
        "This document was already uploaded",
        409,
        cors
      );
    }

    // 6) upload storage (bucket privado)
    const storagePath = buildStoragePath(userId);
    const up = await supabase.storage.from(BUCKET).upload(storagePath, file, {
      contentType: "application/pdf",
      upsert: false,
      cacheControl: "3600",
    });
    if (up.error) {
      return errorResponse(
        "Upload failed",
        "STORAGE_UPLOAD_FAILED",
        up.error.message,
        500,
        cors
      );
    }

    // 7) insert metadados (tratar 23505 -> duplicado por índice único)
    const ins = await supabase
      .from("contract_files")
      .insert({
        user_id: userId,
        title,
        storage_bucket: BUCKET,
        storage_path: storagePath,
        mime_type: "application/pdf",
        size_bytes: file.size,
        sha256,
        meta,
      })
      .select()
      .single();

    if (ins.error) {
      // tentativa de limpeza do arquivo órfão
      try {
        await supabase.storage.from(BUCKET).remove([storagePath]);
      } catch {}
      if (ins.error.code === "23505") {
        return errorResponse(
          "Duplicate file",
          "DUPLICATE_FILE",
          "This document was already uploaded",
          409,
          cors
        );
      }
      return errorResponse(
        "DB insert failed",
        "METADATA_INSERT_FAILED",
        ins.error.message,
        500,
        cors
      );
    }

    // 8) resposta enxuta
    return jsonResponse(
      {
        success: true,
        file: {
          id: ins.data.id,
          title: ins.data.title,
          storage_bucket: ins.data.storage_bucket,
          storage_path: ins.data.storage_path,
          mime_type: ins.data.mime_type,
          size_bytes: ins.data.size_bytes,
          sha256: ins.data.sha256,
          uploaded_at: ins.data.uploaded_at,
          meta: ins.data.meta,
          public_url: null, // bucket privado por padrão
        },
      },
      201,
      cors
    );
  } catch (e) {
    const msg = e instanceof Error ? e.message : String(e);
    return errorResponse(
      "Internal server error",
      "INTERNAL_ERROR",
      msg,
      500,
      cors
    );
  }
});
