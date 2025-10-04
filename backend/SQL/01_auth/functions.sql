SET search_path TO 'public';


-- Cria uma função para lidar com o signup do usuário
CREATE OR REPLACE FUNCTION fn_handle_user_signup()
RETURNS TRIGGER 
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
   INSERT INTO public.users (id, email, full_name)
   VALUES (
      NEW.id, 
      NEW.email, 
      NEW.raw_user_meta_data->>'full_name'
   )
   ON CONFLICT (id) DO UPDATE SET 
      email = EXCLUDED.email, 
      full_name = EXCLUDED.full_name,
      updated_at = NOW();

   RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- Cria uma função para atualizar updated_at na tabela users
CREATE OR REPLACE FUNCTION fn_set_updated_at()
RETURNS TRIGGER 
AS $$
BEGIN
   NEW.updated_at = now();
   RETURN NEW;
END;
$$ LANGUAGE plpgsql;


-- Cria uma função que verifica role do usuário
CREATE OR REPLACE FUNCTION fn_is_admin()
RETURNS BOOLEAN
SECURITY DEFINER
SET search_path = public
AS $$
   SELECT role = 'admin'
   FROM users
   WHERE id = auth.uid()
$$ LANGUAGE sql;


-- Cria uma função para previnir user de subir privilgios e burlar plano
CREATE OR REPLACE FUNCTION fn_prevent_privilege_escalation()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public
AS $$
BEGIN
   -- Só admin pode mudar role/plan
   IF (NEW.role != OLD.role OR NEW.plan != OLD.plan) AND NOT fn_is_admin() THEN
      RAISE EXCEPTION 'Error: Você não tem privilégios para executar essa operação';
   END IF;

   RETURN NEW;
END;
$$ LANGUAGE plpgsql;