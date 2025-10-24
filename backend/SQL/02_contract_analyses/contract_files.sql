CREATE TABLE IF NOT EXISTS contract_files(
  id UUID PRIMARY KEY DEFAULT GEN_RANDOM_UUID(),
  user_id UUID NOT NULL,
  title TEXT,
  storage_bucket TEXT NOT NULL DEFAULT 'contracts',
  storage_path TEXT NOT NULL,
  mime_type TEXT NOT NULL DEFAULT 'application/pdf',
  size_bytes BIGINT CHECK(
    size_bytes IS NULL
    OR size_bytes >= 0
  ),
  sha256 TEXT NOT NULL,
  meta JSONB NOT NULL DEFAULT '{}'::JSONB,
  uploaded_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  -- Relação com a tabela public.users
  CONSTRAINT contract_files_user_fk FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  -- Checks
  CONSTRAINT contract_files_mime_pdf_chk CHECK(mime_type = 'application/pdf'),
  CONSTRAINT contract_files_storage_path_chk CHECK(storage_path ~ '^[A-Za-z0-9/_\.\-]+\.pdf$'),
  CONSTRAINT contract_files_sha256_chk CHECK(sha256 ~ '^[0-9a-f]{64}$')
);

CREATE INDEX IF NOT EXISTS contract_files_user_idx ON contract_files(user_id);
CREATE INDEX IF NOT EXISTS contract_files_uploaded_idx ON contract_files(uploaded_at desc);
CREATE INDEX IF NOT EXISTS contract_files_bucket_path_idx 
  ON contract_files(storage_bucket, storage_path);
CREATE UNIQUE INDEX IF NOT EXISTS contract_files_bucket_path_uniq 
  ON public.contract_files(storage_bucket, storage_path);
CREATE UNIQUE INDEX IF NOT EXISTS contract_files_user_sha256_uniq 
  ON public.contract_files(user_id, sha256) 
  WHERE sha256 IS NOT NULL;