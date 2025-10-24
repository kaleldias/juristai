CREATE TYPE analysis_status AS ENUM ('PENDING', 'RUNNING', 'SUCCEEDED', 'FAILED') 



CREATE TABLE IF NOT EXISTS create_analyses(
  id UUID PRIMARY KEY DEFAULT GEN_RANDOM_UUID(),
  contract_file_id UUID NOT NULL,
  user_id UUID NOT NUL,
  status analysis_status NOT NULL DEFAULT 'PENDING',
  model VARCHAR(100),
  prompt_version TEXT,
  started_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,
  finished_at TIMESTAMPTZ,
  summary JSONB NOT NULL DEFAULT '{}' :JSONB ,
  raw_response JSONB,
  error_message TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT chk_contract_analyses_time
  CHECK (finished_at is null OR finished_at >= started_at),

  CONSTRAINT fk_create_analyses_contract_file_id
  FOREIGN KEY contract_file_id REFERENCES contract_files(id) ON DELETE CASCADE
  
  CONSTRAINT fk_create_analyses_user_id
  FOREIGN KEY user_id REFERENCES users(id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_analyses_user ON contract_analyses(user_id);
CREATE INDEX IF NOT EXISTS idx_contract_analyses_file ON contract_analyses(contract_file_id);
CREATE INDEX IF NOT EXISTS idx_contract_analyses_status ON contract_analyses(status);
CREATE INDEX IF NOT EXISTS idx_contract_analyses_created ON contract_analyses(created_at DESC);