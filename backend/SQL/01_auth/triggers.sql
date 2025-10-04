SET search_path TO 'public';


-- Cria um trigger para lidar com o signup do usuário
CREATE TRIGGER trg_on_auth_user_created
AFTER INSERT ON auth.users
FOR EACH ROW
EXECUTE FUNCTION fn_handle_user_signup();


-- Cria um trigger para atualizar updated_at na tabela users
CREATE TRIGGER trg_on_users_update
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION fn_set_updated_at();


-- Cria um trigger para previnir user de subir privilgios e burlar plano
CREATE TRIGGER trg_prevent_privilege_escalation
BEFORE UPDATE ON users
FOR EACH ROW
EXECUTE FUNCTION fn_prevent_privilege_escalation();