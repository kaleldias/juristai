CREATE TABLE IF NOT EXISTS contract_extracted_text(
  id UUID PRIMARY KEY DEFAULT GEN_RANDOM_UUID(),
  contract_file_id UUID NOT NULL,
  user_id UUID NOT NULL,
  extracted_text TEXT NOT NULL,
  extractor_version INTEGER,
  page_count INTEGER,
  language VARCHAR(50),
  ocr_used BOOLEAN,
  meta JSONB DEFAULT '{}'::JSONB,
  char_count INTEGER GENERATED ALWAYS AS (CHAR_LENGTH(extracted_text)) stored,
  created_at TIMESTAMPTZ CURRENT_TIMESTAMP NOT NULL,
  
  CONSTRAINT fk_contract_extracted_text_file_id
  FOREIGN KEY(contract_file_id) REFERENCES contract_files(id) ON DELETE CASCADE,
  
  CONSTRAINT fk_contract_extracted_text_user_id 
  FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
  -- Garante 1:1 com contract_files
  CONSTRAINT uniq_contract_extracted_text_file UNIQUE (contract_file_id)
);

CREATE INDEX IF NOT EXISTS idx_contract_extracted_text_user 
  ON contract_extracted_text(user_id);
  
CREATE INDEX IF NOT EXISTS idx_constract_extracted_text_created
  ON contract_extracted_text(created_at DESC);