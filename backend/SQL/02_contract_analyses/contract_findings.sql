CREATE TYPE risk_level AS ENUM ('LOW', 'MEDIUM', 'HIGH');

CREATE TABLE IF NOT EXISTS contract_findings(
  id UUID PRIMARY KEY DEFAULT GEN_RANDOM_UUID(),
  analyses_id UUID NOT NULL,
  user_id UUID NOT NULL,
  type VARCHAR(200) NOT NULL,
  risk risk_level NOT NULL,
  title VARCHAR(255) NOT NULL,
  description TEXT,
  recommendation TEXT,
  source_span JSONB DEFAULT '{}'::JSONB,
  extra JSONB DEFAULT '{}'::JSONB,
  created_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP,

  CONSTRAINT fk_contract_findings_analyses_id
  FOREIGN KEY (analyses_id) REFERENCES contract_analyses (id) ON DELETE CASCADE,
  CONSTRAINT fk_contract_findings_user_id
  FOREIGN KEY (user_id) REFERENCES users (id) ON DELETE CASCADE
);

CREATE INDEX IF NOT EXISTS idx_contract_findings_analyses ON contract_findings (analyses_id);
CREATE INDEX IF NOT EXISTS idx_contract_findings_user ON contract_findings (user_id);
CREATE INDEX IF NOT EXISTS idx_contract_findings_risk ON contract_findings (risk);
CREATE INDEX IF NOT EXISTS idx_contract_findings_extra ON contract_findings ((extra->>'clause_refs'));