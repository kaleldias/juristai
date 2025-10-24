-- ====== POLICIES CONTRACT_FILES ======
ALTER TABLE contract_files ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS contract_files_owner_read ON contract_files;
DROP POLICY IF EXISTS contract_files_owner_insert ON contract_files;
DROP POLICY IF EXISTS contract_files_owner_delete ON contract_files;

-- Policy: [SELECT] dono vê seus próprios registros; admin vê tudo
CREATE POLICY contract_files_owner_read 
ON contract_files FOR SELECT
USING (user_id = auth.uid() OR fn_is_admin());

-- Policy: [INSERT] apenas o próprio usuário (ou admin) pode inserir
CREATE POLICY contract_files_owner_insert 
ON contract_files FOR INSERT
WITH CHECK (user_id = auth.uid() OR fn_is_admin());

-- Policy: [DELETE] apenas o próprio usuário (ou admin) pode deletar um contrato enviado
CREATE POLICY contract_files_owner_delete
ON contract_files FOR DELETE
USING (user_id = auth.uid() OR fn_is_admin());



-- ====== POLICIES CONTRACT_EXTRACTED_TEXT (CET) ======
ALTER TABLE contract_extracted_text ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS cet_owner_read ON contract_extracted_text;
DROP POLICY IF EXISTS cet_owner_insert ON contract_extracted_text;


CREATE POLICY cet_owner_read
ON contract_extracted_text FOR SELECT
USING (user_id = auth.uid() or fn_is_admin());

CREATE POLICY cet_owner_insert
ON contract_extracted_text FOR INSERT
WITH CHECK (user_id = auth.uid() or fn_is_admin());



-- ====== POLICIES CONTRACT_ANALYSES (CA) ======
ALTER TABLE contract_analyses ENABLE ROW LEVEL SECURITY;

DROP POLICY IF EXISTS ca_owner_read ON contract_analyses;
DROP POLICY IF EXISTS ca_owner_insert ON contract_analyses;


CREATE POLICY ca_owner_read
ON contract_analyses FOR SELECT
USING (id = auth.uid() OR fn_is_admin());

CREATE POLICY ca_owner_insert
ON contract_analyses FOR INSERT
WITH CHECK (id = auth.uid() OR fn_is_admin())
