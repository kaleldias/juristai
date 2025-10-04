SET search_path TO 'public';

ALTER TABLE users ENABLE ROW LEVEL SECURITY;

-- ========== USER POLICIES ==========
-- Policy: usuário vê apenas seus dados
CREATE POLICY user_select_own
ON users FOR SELECT TO authenticated
USING (auth.uid() = id);

-- Policy: usuário atualiza apenas seus dados
CREATE POLICY user_update_own
ON users FOR UPDATE TO authenticated
USING (auth.uid() = id);
WITH CHECK(auth.uid() = id);




-- ========== ADMIN POLICIES ==========
-- Policy: admin gerencia tudo
CREATE POLICY admins_all
ON users FOR ALL TO authenticated
USING (fn_is_admin())
WITH CHECK (fn_is_admin());

